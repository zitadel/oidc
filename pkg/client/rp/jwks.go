package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/caos/oidc/pkg/utils"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

func NewRemoteKeySet(client *http.Client, jwksURL string) oidc.KeySet {
	return &remoteKeySet{httpClient: client, jwksURL: jwksURL}
}

type remoteKeySet struct {
	jwksURL    string
	httpClient *http.Client
	defaultAlg string

	// guard all other fields
	mu sync.Mutex

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *inflight

	// A set of cached keys and their expiry.
	cachedKeys []jose.JSONWebKey
}

// inflight is used to wait on some in-flight request from multiple goroutines.
type inflight struct {
	doneCh chan struct{}

	keys []jose.JSONWebKey
	err  error
}

func newInflight() *inflight {
	return &inflight{doneCh: make(chan struct{})}
}

// wait returns a channel that multiple goroutines can receive on. Once it returns
// a value, the inflight request is done and result() can be inspected.
func (i *inflight) wait() <-chan struct{} {
	return i.doneCh
}

// done can only be called by a single goroutine. It records the result of the
// inflight request and signals other goroutines that the result is safe to
// inspect.
func (i *inflight) done(keys []jose.JSONWebKey, err error) {
	i.keys = keys
	i.err = err
	close(i.doneCh)
}

// result cannot be called until the wait() channel has returned a value.
func (i *inflight) result() ([]jose.JSONWebKey, error) {
	return i.keys, i.err
}

func (r *remoteKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	if alg == "" {
		alg = r.defaultAlg
	}
	keys := r.keysFromCache()
	key, ok := oidc.FindKey(keyID, oidc.KeyUseSignature, alg, keys...)
	if ok && keyID != "" {
		payload, err := jws.Verify(&key)
		return payload, err
	}

	keys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys %v", err)
	}
	key, ok = oidc.FindKey(keyID, oidc.KeyUseSignature, alg, keys...)
	if ok {
		payload, err := jws.Verify(&key)
		return payload, err
	}
	return nil, errors.New("invalid key")
}

func (r *remoteKeySet) keysFromCache() (keys []jose.JSONWebKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cachedKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (r *remoteKeySet) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
	// Need to lock to inspect the inflight request field.
	r.mu.Lock()
	// If there's not a current inflight request, create one.
	if r.inflight == nil {
		r.inflight = newInflight()

		// This goroutine has exclusive ownership over the current inflight
		// request. It releases the resource by nil'ing the inflight field
		// once the goroutine is done.
		go r.updateKeys(ctx)
	}
	inflight := r.inflight
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-inflight.wait():
		return inflight.result()
	}
}

func (r *remoteKeySet) updateKeys(ctx context.Context) {
	// Sync keys and finish inflight when that's done.
	keys, err := r.fetchRemoteKeys(ctx)

	r.inflight.done(keys, err)

	// Lock to update the keys and indicate that there is no longer an
	// inflight request.
	r.mu.Lock()
	defer r.mu.Unlock()

	if err == nil {
		r.cachedKeys = keys
	}

	// Free inflight so a different request can run.
	r.inflight = nil
}

func (r *remoteKeySet) fetchRemoteKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequest("GET", r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %v", err)
	}

	keySet := new(jsonWebKeySet)
	if err = utils.HttpRequest(r.httpClient, req, keySet); err != nil {
		return nil, fmt.Errorf("oidc: failed to get keys: %v", err)
	}
	return keySet.Keys, nil
}

//jsonWebKeySet is an alias for jose.JSONWebKeySet which ignores unknown key types (kty)
type jsonWebKeySet jose.JSONWebKeySet

//UnmarshalJSON overrides the default jose.JSONWebKeySet method to ignore any error
//which might occur because of unknown key types (kty)
func (k *jsonWebKeySet) UnmarshalJSON(data []byte) (err error) {
	var raw rawJSONWebKeySet
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}
	for _, key := range raw.Keys {
		webKey := new(jose.JSONWebKey)
		err = webKey.UnmarshalJSON(key)
		if err == nil {
			k.Keys = append(k.Keys, *webKey)
		}
	}
	return nil
}

type rawJSONWebKeySet struct {
	Keys []json.RawMessage `json:"keys"`
}

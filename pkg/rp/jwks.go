package rp

import (
	"context"
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
	// We don't support JWTs signed with multiple signatures.
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	keys := r.keysFromCache()
	payload, err, ok := checkKey(keyID, keys, jws)
	if ok {
		return payload, err
	}

	keys, err = r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys %v", err)
	}

	payload, err, ok = checkKey(keyID, keys, jws)
	if !ok {
		return nil, errors.New("invalid kid")
	}
	return payload, err
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

	keySet := new(jose.JSONWebKeySet)
	if err = utils.HttpRequest(r.httpClient, req, keySet); err != nil {
		return nil, fmt.Errorf("oidc: failed to get keys: %v", err)
	}

	return keySet.Keys, nil
}

func checkKey(keyID string, keys []jose.JSONWebKey, jws *jose.JSONWebSignature) ([]byte, error, bool) {
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			payload, err := jws.Verify(&key)
			return payload, err, true
		}
	}
	return nil, nil, false
}

package rp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/client"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const joseUnknownKeyTypeErrMsg = "go-jose/go-jose: unknown json web key type '"

func NewRemoteKeySet(client *http.Client, jwksURL string, opts ...func(*remoteKeySet)) oidc.KeySet {
	keyset := &remoteKeySet{httpClient: client, jwksURL: jwksURL}
	for _, opt := range opts {
		opt(keyset)
	}
	return keyset
}

// SkipRemoteCheck will suppress checking for new remote keys if signature validation fails with cached keys
// and no kid header is set in the JWT
//
// this might be handy to save some unnecessary round trips in cases where the JWT does not contain a kid header and
// there is only a single remote key
// please notice that remote keys will then only be fetched if cached keys are empty
func SkipRemoteCheck() func(set *remoteKeySet) {
	return func(set *remoteKeySet) {
		set.skipRemoteCheck = true
	}
}

type remoteKeySet struct {
	jwksURL         string
	httpClient      *http.Client
	defaultAlg      string
	skipRemoteCheck bool

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
	ctx, span := client.Tracer.Start(ctx, "VerifySignature")
	defer span.End()

	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	if alg == "" {
		alg = r.defaultAlg
	}
	payload, err := r.verifySignatureCached(jws, keyID, alg)
	if payload != nil {
		return payload, nil
	}
	if err != nil {
		return nil, err
	}
	return r.verifySignatureRemote(ctx, jws, keyID, alg)
}

// verifySignatureCached checks for a matching key in the cached key list
//
// if there is only one possible, it tries to verify the signature and will return the payload if successful
//
// it only returns an error if signature validation fails and keys exactMatch which is if either:
// - both kid are empty and skipRemoteCheck is set to true
// - or both (JWT and JWK) kid are equal
//
// otherwise it will return no error (so remote keys will be loaded)
func (r *remoteKeySet) verifySignatureCached(jws *jose.JSONWebSignature, keyID, alg string) ([]byte, error) {
	keys := r.keysFromCache()
	if len(keys) == 0 {
		return nil, nil
	}
	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, keys...)
	if err != nil {
		// no key / multiple found, try with remote keys
		return nil, nil //nolint:nilerr
	}
	payload, err := jws.Verify(&key)
	if payload != nil {
		return payload, nil
	}
	if !r.exactMatch(key.KeyID, keyID) {
		// no exact key match, try getting better match with remote keys
		return nil, nil
	}
	return nil, fmt.Errorf("signature verification failed: %w", err)
}

func (r *remoteKeySet) exactMatch(jwkID, jwsID string) bool {
	if jwkID == "" && jwsID == "" {
		return r.skipRemoteCheck
	}
	return jwkID == jwsID
}

func (r *remoteKeySet) verifySignatureRemote(ctx context.Context, jws *jose.JSONWebSignature, keyID, alg string) ([]byte, error) {
	ctx, span := client.Tracer.Start(ctx, "verifySignatureRemote")
	defer span.End()

	keys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch key for signature validation: %w", err)
	}
	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, keys...)
	if err != nil {
		return nil, fmt.Errorf("unable to validate signature: %w", err)
	}
	payload, err := jws.Verify(&key)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return payload, nil
}

func (r *remoteKeySet) keysFromCache() (keys []jose.JSONWebKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cachedKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (r *remoteKeySet) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
	ctx, span := client.Tracer.Start(ctx, "keysFromRemote")
	defer span.End()

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
	ctx, span := client.Tracer.Start(ctx, "updateKeys")
	defer span.End()

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
	ctx, span := client.Tracer.Start(ctx, "fetchRemoteKeys")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, "GET", r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %v", err)
	}

	keySet := new(jsonWebKeySet)
	if err = httphelper.HttpRequest(r.httpClient, req, keySet); err != nil {
		return nil, fmt.Errorf("oidc: failed to get keys: %v", err)
	}
	return keySet.Keys, nil
}

// jsonWebKeySet is an alias for jose.JSONWebKeySet which ignores unknown key types (kty)
type jsonWebKeySet jose.JSONWebKeySet

// UnmarshalJSON overrides the default jose.JSONWebKeySet method to ignore any error
// which might occur because of unknown key types (kty)
func (k *jsonWebKeySet) UnmarshalJSON(data []byte) (err error) {
	var raw rawJSONWebKeySet
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return fmt.Errorf("oidc: failed to unmarshall key set: %w", err)
	}
	for i, key := range raw.Keys {
		webKey := new(jose.JSONWebKey)
		if err = webKey.UnmarshalJSON(key); err != nil {
			if strings.HasPrefix(err.Error(), joseUnknownKeyTypeErrMsg) {
				continue
			}

			return fmt.Errorf("oidc: failed to unmarshal key %d from set: %w", i, err)
		}

		k.Keys = append(k.Keys, *webKey)
	}
	return nil
}

type rawJSONWebKeySet struct {
	Keys []json.RawMessage `json:"keys"`
}

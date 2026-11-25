package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v4/pkg/client"
	httphelper "github.com/zitadel/oidc/v4/pkg/http"
	"github.com/zitadel/oidc/v4/pkg/oidc"
)

func NewRemoteKeySet(client *http.Client, jwksURL string, opts ...func(*remoteKeySet)) oidc.KeySet {
	keyset := &remoteKeySet{httpClient: client, jwksURL: jwksURL}
	for _, opt := range opts {
		opt(keyset)
	}
	return keyset
}

// SkipRemoteCheck will suppress checking for new remote keys if signature validation fails with cached keys
// and no kid header is set in the JWT.
//
// This might be handy to save some unnecessary round trips in cases where the JWT does not contain a kid header and
// there is only a single remote key.
// Please notice that remote keys will then only be fetched if cached keys are empty or expired (see CacheTTL).
func SkipRemoteCheck() func(set *remoteKeySet) {
	return func(set *remoteKeySet) {
		set.skipRemoteCheck = true
	}
}

// CacheTTL sets the duration the fetched remote keys are used for, counted from
// the start of the fetch. Once it has passed, the next signature verification
// fetches the keys again and waits for the result, so keys removed by the issuer
// stop being accepted.
//
// If that fetch fails, the cached keys are kept and used until a later fetch
// succeeds. The next attempt is made after a back-off of 10 seconds, so an
// issuer that is down or rate limiting isn't called on every verification.
//
// Verifications running at the same time share a single fetch. It isn't
// canceled together with the request that started it, so the http.Client
// should have a timeout.
//
// By default (or with a ttl <= 0) the cached keys don't expire. Independent of
// the ttl, the keys are fetched again when the cached ones can't be used for a
// token, for example when none of them has the token's kid or a token without
// kid matches several keys.
func CacheTTL(ttl time.Duration) func(set *remoteKeySet) {
	return func(set *remoteKeySet) {
		set.cacheTTL = ttl
	}
}

// cacheRefreshBackoff is how long the expired keys are still used after a
// failed refresh before the next one is attempted (see CacheTTL).
const cacheRefreshBackoff = 10 * time.Second

type remoteKeySet struct {
	jwksURL         string
	httpClient      *http.Client
	defaultAlg      string
	skipRemoteCheck bool
	cacheTTL        time.Duration

	// guard all other fields
	mu sync.Mutex

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *inflight

	// A set of cached keys and their expiry.
	cachedKeys  []jose.JSONWebKey
	cacheExpiry time.Time
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
	if err := r.refreshExpiredKeys(ctx); err != nil {
		return nil, err
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

// refreshExpiredKeys fetches the keys again if the CacheTTL has passed.
// If that fails, the cached keys are kept and updateKeys delays the next
// attempt, so it only returns an error if ctx is done.
func (r *remoteKeySet) refreshExpiredKeys(ctx context.Context) error {
	r.mu.Lock()
	expired := r.cacheExpired()
	r.mu.Unlock()
	if !expired {
		return nil
	}
	_, _ = r.keysFromRemote(ctx)
	return ctx.Err()
}

// cacheExpired reports whether the cached keys are older than the CacheTTL.
// r.mu must be held.
func (r *remoteKeySet) cacheExpired() bool {
	return r.cacheTTL > 0 && len(r.cachedKeys) > 0 && !time.Now().Before(r.cacheExpiry)
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
		// once the goroutine is done. Other goroutines may be waiting for
		// it, so it must not be canceled together with this request.
		go r.updateKeys(context.WithoutCancel(ctx))
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
	start := time.Now()
	keys, err := r.fetchRemoteKeys(ctx)

	// Lock to update the keys and indicate that there is no longer an
	// inflight request.
	r.mu.Lock()
	defer r.mu.Unlock()

	if err == nil {
		r.cachedKeys = keys
		// Round(0) drops the monotonic clock reading, so the expiry also
		// counts the time the machine was suspended.
		r.cacheExpiry = start.Add(r.cacheTTL).Round(0)
	} else if r.cacheExpired() {
		// Keep using the expired keys for now and don't retry right away.
		r.cacheExpiry = time.Now().Add(cacheRefreshBackoff).Round(0)
	}

	// Finish inflight only after the cache is updated, so the waiters and
	// the next request see the new keys, and free it so a different
	// request can run.
	r.inflight.done(keys, err)
	r.inflight = nil
}

func (r *remoteKeySet) fetchRemoteKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	ctx, span := client.Tracer.Start(ctx, "fetchRemoteKeys")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, "GET", r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %w", err)
	}

	keySet := new(jsonWebKeySet)
	if err = httphelper.HttpRequest(r.httpClient, req, keySet); err != nil {
		return nil, fmt.Errorf("oidc: failed to get keys: %w", err)
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
			if errors.Is(err, jose.ErrUnsupportedKeyType) {
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

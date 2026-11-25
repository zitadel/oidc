package rp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tu "github.com/zitadel/oidc/v4/internal/testutil"
	httphelper "github.com/zitadel/oidc/v4/pkg/http"
	"github.com/zitadel/oidc/v4/pkg/oidc"
)

func TestJsonWebKeySet_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		wantKeyLen int
		wantErr    bool
		errPrefix  string
	}{
		{
			name:       "valid key set",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "empty key set",
			jsonData:   `{"keys":[]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "unknown key type",
			jsonData:   `{"keys":[{"kty":"UNKNOWN","use":"sig","kid":"key1"}]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "mixed valid and unknown key types",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"},{"kty":"UNKNOWN","use":"sig","kid":"key2"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "invalid json",
			jsonData:   `{"keys":[{]`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshall key set: ",
		},
		{
			name:       "other error during key unmarshal",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256"}]}`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshal key 0 from set: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keySet jsonWebKeySet
			err := keySet.UnmarshalJSON([]byte(tt.jsonData))

			if tt.wantErr {
				assert.Error(t, err)
				assert.NotErrorIs(t, err, jose.ErrUnsupportedKeyType)
				assert.True(t, strings.HasPrefix(err.Error(), tt.errPrefix))

			} else {
				assert.NoError(t, err)
				assert.Len(t, keySet.Keys, tt.wantKeyLen)
			}
		})
	}
}

func TestRemoteKeySet_VerifySignature_WrapsFetchError(t *testing.T) {
	errTransport := errors.New("connection refused")

	tests := []struct {
		name      string
		transport roundTripFunc
		wantErr   error
	}{
		{
			name: "transport error",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errTransport
			},
			wantErr: errTransport,
		},
		{
			name: "response too large",
			transport: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat(" ", int(httphelper.MaxResponseBodySize)+1))),
					Request:    r,
				}, nil
			},
			wantErr: httphelper.ErrResponseBodyTooLarge,
		},
		{
			name: "oauth error response",
			transport: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Body:       io.NopCloser(strings.NewReader(`{"error":"server_error","error_description":"key store unavailable"}`)),
					Request:    r,
				}, nil
			},
			wantErr: &oidc.Error{ErrorType: oidc.ServerError, Description: "key store unavailable"},
		},
	}

	payload, err := tu.Signer.Sign([]byte(`{"sub":"subject"}`))
	require.NoError(t, err)
	token, err := payload.CompactSerialize()
	require.NoError(t, err)
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{tu.SignatureAlgorithm})
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keySet := NewRemoteKeySet(&http.Client{Transport: tt.transport}, "https://example.com/keys")
			_, err := keySet.VerifySignature(context.Background(), jws)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// testJWKS serves a key set through an in-memory transport, so the tests can
// run in a synctest bubble, whose fake clock doesn't advance while a goroutine
// waits on a real socket.
type testJWKS struct {
	keys    []jose.JSONWebKey
	status  int           // http.StatusOK if not set
	latency time.Duration // how long a fetch takes
	release chan struct{} // if set, fetches wait until it's closed
	fetches atomic.Int32
}

func (s *testJWKS) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		s.fetches.Add(1)
		if s.release != nil {
			select {
			case <-s.release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		time.Sleep(s.latency)
		if s.status != 0 && s.status != http.StatusOK {
			return &http.Response{
				StatusCode: s.status,
				Status:     http.StatusText(s.status),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    r,
			}, nil
		}
		body, err := json.Marshal(jose.JSONWebKeySet{Keys: s.keys})
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    r,
		}, nil
	})}
}

// testJWS returns a token signed by tu.Signer, with kid "1".
func testJWS(t *testing.T) *jose.JSONWebSignature {
	t.Helper()
	signed, err := tu.Signer.Sign([]byte(`{"sub":"subject"}`))
	require.NoError(t, err)
	token, err := signed.CompactSerialize()
	require.NoError(t, err)
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{tu.SignatureAlgorithm})
	require.NoError(t, err)
	return jws
}

// rotatedKey replaces tu.WebKey after a key rotation by the issuer.
func rotatedKey() jose.JSONWebKey {
	key := tu.WebKey.Public()
	key.KeyID = "2"
	return key
}

func TestRemoteKeySet_CacheTTL(t *testing.T) {
	const ttl = time.Hour
	jws := testJWS(t)

	tests := []struct {
		name        string
		opts        []func(*remoteKeySet)
		rotate      bool          // the issuer rotates out the token's key after the first verification
		elapsed     time.Duration // since the first verification started
		wantErr     error
		wantFetches int32
	}{
		{
			name:        "no ttl keeps the cached key",
			rotate:      true,
			elapsed:     2 * ttl,
			wantFetches: 1,
		},
		{
			name:        "cached key kept within the ttl",
			opts:        []func(*remoteKeySet){CacheTTL(ttl)},
			rotate:      true,
			elapsed:     ttl - time.Second,
			wantFetches: 1,
		},
		{
			name:    "rotated key rejected after the ttl",
			opts:    []func(*remoteKeySet){CacheTTL(ttl)},
			rotate:  true,
			elapsed: ttl,
			wantErr: oidc.ErrKeyNone,
			// the refresh, then the usual refetch for a kid that isn't cached
			wantFetches: 3,
		},
		{
			name:        "key still published after the ttl",
			opts:        []func(*remoteKeySet){CacheTTL(ttl)},
			elapsed:     ttl,
			wantFetches: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// a fetch takes a second, the ttl counts from its start
				issuer := &testJWKS{keys: []jose.JSONWebKey{tu.WebKey.Public()}, latency: time.Second}
				keySet := NewRemoteKeySet(issuer.client(), "https://issuer.example/keys", tt.opts...)

				start := time.Now()
				_, err := keySet.VerifySignature(context.Background(), jws)
				require.NoError(t, err)

				if tt.rotate {
					issuer.keys = []jose.JSONWebKey{rotatedKey()}
				}
				time.Sleep(time.Until(start.Add(tt.elapsed)))

				_, err = keySet.VerifySignature(context.Background(), jws)
				if tt.wantErr != nil {
					assert.ErrorIs(t, err, tt.wantErr)
				} else {
					assert.NoError(t, err)
				}
				assert.Equal(t, tt.wantFetches, issuer.fetches.Load())
			})
		})
	}
}

func TestRemoteKeySet_CacheTTL_FailedRefresh(t *testing.T) {
	const ttl = time.Hour
	jws := testJWS(t)

	synctest.Test(t, func(t *testing.T) {
		issuer := &testJWKS{keys: []jose.JSONWebKey{tu.WebKey.Public()}}
		keySet := NewRemoteKeySet(issuer.client(), "https://issuer.example/keys", CacheTTL(ttl))
		verify := func() error {
			_, err := keySet.VerifySignature(context.Background(), jws)
			return err
		}
		require.NoError(t, verify())

		// the refresh fails, the cached key is still used
		issuer.status = http.StatusServiceUnavailable
		time.Sleep(ttl)
		assert.NoError(t, verify())
		assert.EqualValues(t, 2, issuer.fetches.Load())

		// no new attempt during the back-off
		time.Sleep(cacheRefreshBackoff - time.Second)
		assert.NoError(t, verify())
		assert.EqualValues(t, 2, issuer.fetches.Load())

		// the next attempt fails as well
		time.Sleep(time.Second)
		assert.NoError(t, verify())
		assert.EqualValues(t, 3, issuer.fetches.Load())

		// the issuer is back and has rotated out the token's key
		issuer.status = http.StatusOK
		issuer.keys = []jose.JSONWebKey{rotatedKey()}
		time.Sleep(cacheRefreshBackoff)
		assert.ErrorIs(t, verify(), oidc.ErrKeyNone)
		// the refresh, then the usual refetch for a kid that isn't cached
		assert.EqualValues(t, 5, issuer.fetches.Load())
	})
}

func TestRemoteKeySet_SharedFetch(t *testing.T) {
	jws := testJWS(t)

	t.Run("concurrent verifications after the ttl", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			issuer := &testJWKS{keys: []jose.JSONWebKey{tu.WebKey.Public()}}
			keySet := NewRemoteKeySet(issuer.client(), "https://issuer.example/keys", CacheTTL(time.Hour))
			_, err := keySet.VerifySignature(context.Background(), jws)
			require.NoError(t, err)

			time.Sleep(time.Hour)
			issuer.release = make(chan struct{})
			var wg sync.WaitGroup
			for range 10 {
				wg.Go(func() {
					_, err := keySet.VerifySignature(context.Background(), jws)
					assert.NoError(t, err)
				})
			}
			// all of them wait for the same fetch
			synctest.Wait()
			close(issuer.release)
			wg.Wait()
			assert.EqualValues(t, 2, issuer.fetches.Load())
		})
	})

	t.Run("request that started the fetch is canceled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			issuer := &testJWKS{keys: []jose.JSONWebKey{tu.WebKey.Public()}, release: make(chan struct{})}
			keySet := NewRemoteKeySet(issuer.client(), "https://issuer.example/keys")

			ctx, cancel := context.WithCancel(context.Background())
			first := make(chan error)
			go func() {
				_, err := keySet.VerifySignature(ctx, jws)
				first <- err
			}()
			synctest.Wait()
			second := make(chan error)
			go func() {
				_, err := keySet.VerifySignature(context.Background(), jws)
				second <- err
			}()
			synctest.Wait()

			cancel()
			assert.ErrorIs(t, <-first, context.Canceled)
			close(issuer.release)
			assert.NoError(t, <-second)
			assert.EqualValues(t, 1, issuer.fetches.Load())
		})
	})
}

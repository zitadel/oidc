package rp

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tu "github.com/zitadel/oidc/v3/internal/testutil"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Generated locally for tests; no provider keys or tokens are used.
const unsupportedCurveJWK = `{"kty":"EC","crv":"secp256k1","alg":"ES256K","use":"sig","kid":"unsupported","x":"NB-dIzZaYHJ_auaS75Ww5BVK6pEB7GuJML9xuqCI9GM","y":"9ByV0-2xr158wJAcO2ILFMyQAIUWmwqU7BeYOPmu58U"}`

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
			name:       "unsupported elliptic curve",
			jsonData:   `{"keys":[` + unsupportedCurveJWK + `]}`,
			wantKeyLen: 0,
		},
		{
			name:      "malformed supported elliptic curve",
			jsonData:  `{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256"}]}`,
			wantErr:   true,
			errPrefix: "oidc: failed to unmarshal key 0 from set: ",
		},
		{
			name:      "malformed key after unsupported curve",
			jsonData:  `{"keys":[` + unsupportedCurveJWK + `,{"kty":"RSA","alg":"RS256"}]}`,
			wantErr:   true,
			errPrefix: "oidc: failed to unmarshal key 1 from set: ",
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
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{tu.SignatureAlgorithm})
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keySet := NewRemoteKeySet(&http.Client{Transport: tt.transport}, "https://example.com/keys")
			_, err := keySet.VerifySignature(context.Background(), jws)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestRemoteKeySet_UnsupportedEllipticCurve(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)
	ecKey := mustECKey(t, elliptic.P256())
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keys := []jose.JSONWebKey{
		{Key: rsaKey.Public(), KeyID: "rsa", Algorithm: string(jose.RS256), Use: "sig"},
		{Key: ecKey.Public(), KeyID: "ec", Algorithm: string(jose.ES256), Use: "sig"},
		{Key: edPublic, KeyID: "ed", Algorithm: string(jose.EdDSA), Use: "sig"},
	}
	var supported []json.RawMessage
	for _, key := range keys {
		raw, err := json.Marshal(key)
		require.NoError(t, err)
		supported = append(supported, raw)
	}
	payload := []byte(`{"sub":"test-subject"}`)
	sign := func(key any, alg jose.SignatureAlgorithm, kid string) *jose.JSONWebSignature {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
		require.NoError(t, err)
		jws, err := signer.Sign(payload)
		require.NoError(t, err)
		compact, err := jws.CompactSerialize()
		require.NoError(t, err)
		parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{alg})
		require.NoError(t, err)
		return parsed
	}
	valid := []*jose.JSONWebSignature{
		sign(rsaKey, jose.RS256, "rsa"),
		sign(ecKey, jose.ES256, "ec"),
		sign(edPrivate, jose.EdDSA, "ed"),
	}
	wrongSignature := sign(mustRSAKey(t, 2048), jose.RS256, "rsa")
	unknownKey := sign(rsaKey, jose.RS256, "unsupported")

	for _, position := range []int{0, 1, 3} {
		t.Run([]string{"first", "middle", "", "last"}[position], func(t *testing.T) {
			mixed := make([]json.RawMessage, 0, 4)
			mixed = append(mixed, supported[:position]...)
			mixed = append(mixed, json.RawMessage(unsupportedCurveJWK))
			mixed = append(mixed, supported[position:]...)
			raw, err := json.Marshal(rawJSONWebKeySet{Keys: mixed})
			require.NoError(t, err)

			var parsed jsonWebKeySet
			require.NoError(t, json.Unmarshal(raw, &parsed))
			require.Len(t, parsed.Keys, 3)
			for i, key := range parsed.Keys {
				assert.Equal(t, keys[i].KeyID, key.KeyID)
				assert.Equal(t, keys[i].Algorithm, key.Algorithm)
				assert.True(t, key.Valid())
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			remote := NewRemoteKeySet(server.Client(), server.URL)
			for i, jws := range valid {
				verified, err := remote.VerifySignature(context.Background(), jws)
				require.NoError(t, err, "supported algorithm %s", keys[i].Algorithm)
				assert.Equal(t, payload, verified)
			}
			_, err = remote.VerifySignature(context.Background(), wrongSignature)
			assert.ErrorContains(t, err, "signature verification failed")
			_, err = remote.VerifySignature(context.Background(), unknownKey)
			assert.ErrorContains(t, err, "unable to validate signature")
		})
	}

	t.Run("no supported keys", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[` + unsupportedCurveJWK + `]}`))
		}))
		defer server.Close()
		_, err := NewRemoteKeySet(server.Client(), server.URL).VerifySignature(context.Background(), valid[0])
		assert.ErrorContains(t, err, "unable to validate signature")
	})
}

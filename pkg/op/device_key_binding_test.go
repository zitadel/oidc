package op_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const deviceTokenHTU = "https://localhost:9998/oauth/token"

// completeBoundDeviceAuthorization stores an approved, key-bound device
// authorization and returns the device code.
func completeBoundDeviceAuthorization(t *testing.T, deviceCode, userCode, jkt string, scopes []string) {
	t.Helper()
	s := testProvider.Storage().(*storage.Storage)
	require.NoError(t, s.StoreBoundKeyDeviceAuthorization(
		context.Background(), "native", deviceCode, userCode, time.Now().Add(time.Minute), scopes, jkt))
	require.NoError(t, s.CompleteDeviceAuthorization(context.Background(), userCode, "id1"))
}

func deviceTokenRequest(t *testing.T, deviceCode, proof string) *httptest.ResponseRecorder {
	t.Helper()
	values := make(url.Values)
	values.Set("client_id", "native")
	values.Set("grant_type", string(oidc.GrantTypeDeviceCode))
	values.Set("device_code", deviceCode)

	r := httptest.NewRequest(http.MethodPost, deviceTokenHTU, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		r.Header.Set(oidc.DPoPHeader, proof)
	}
	r = r.WithContext(op.ContextWithIssuer(r.Context(), testIssuer))

	w := httptest.NewRecorder()
	op.DeviceAccessToken(w, r, testProvider)
	return w
}

// TestDeviceAccessToken_BoundKey covers OpenID Connect Key Binding 1.0 Section
// 3.3: a key-bound device authorization must require a DPoP proof whose c_s256
// is the hash of the device code, and must return a key-bound ID Token.
func TestDeviceAccessToken_BoundKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jkt := jktOf(t, &key.PublicKey)
	scopes := []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}

	t.Run("valid proof returns a bound ID Token", func(t *testing.T) {
		const deviceCode, userCode = "bound-ok", "bound-ok-user"
		completeBoundDeviceAuthorization(t, deviceCode, userCode, jkt, scopes)

		opts := defaultDPoPProofOpts()
		opts.htu = deviceTokenHTU
		opts.codeHash = oidc.CodeHash(deviceCode)
		proof := signDPoPProof(t, key, jose.ES256, opts)

		result := deviceTokenRequest(t, deviceCode, proof).Result()
		body, _ := io.ReadAll(result.Body)
		require.Less(t, result.StatusCode, 300, string(body))

		var response oidc.AccessTokenResponse
		require.NoError(t, json.Unmarshal(body, &response))
		require.NotEmpty(t, response.IDToken)

		// The ID Token must be marked and bound.
		signed, err := jose.ParseSigned(response.IDToken, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		typ, _ := signed.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string)
		assert.Equal(t, string(oidc.IDTokenTypeDPoP), typ)

		var claims oidc.IDTokenClaims
		require.NoError(t, json.Unmarshal(signed.UnsafePayloadWithoutVerification(), &claims))
		require.NotNil(t, claims.Confirmation)

		var confirmedJWK jose.JSONWebKey
		require.NoError(t, json.Unmarshal(claims.Confirmation.JWK, &confirmedJWK))
		boundJKT, err := oidc.JWKThumbprint(&confirmedJWK)
		require.NoError(t, err)
		assert.Equal(t, jkt, boundJKT)
	})

	t.Run("missing proof is rejected", func(t *testing.T) {
		const deviceCode, userCode = "bound-noproof", "bound-noproof-user"
		completeBoundDeviceAuthorization(t, deviceCode, userCode, jkt, scopes)

		result := deviceTokenRequest(t, deviceCode, "").Result()
		body, _ := io.ReadAll(result.Body)
		assert.GreaterOrEqual(t, result.StatusCode, 400, string(body))
		assert.Contains(t, string(body), string(oidc.InvalidDPoPProof))
	})

	t.Run("proof from a different key is rejected", func(t *testing.T) {
		const deviceCode, userCode = "bound-wrongkey", "bound-wrongkey-user"
		completeBoundDeviceAuthorization(t, deviceCode, userCode, jkt, scopes)

		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		opts := defaultDPoPProofOpts()
		opts.htu = deviceTokenHTU
		opts.codeHash = oidc.CodeHash(deviceCode)
		proof := signDPoPProof(t, other, jose.ES256, opts)

		result := deviceTokenRequest(t, deviceCode, proof).Result()
		body, _ := io.ReadAll(result.Body)
		assert.GreaterOrEqual(t, result.StatusCode, 400, string(body))
	})

	t.Run("proof bound to another code is rejected", func(t *testing.T) {
		const deviceCode, userCode = "bound-wrongcode", "bound-wrongcode-user"
		completeBoundDeviceAuthorization(t, deviceCode, userCode, jkt, scopes)

		opts := defaultDPoPProofOpts()
		opts.htu = deviceTokenHTU
		opts.codeHash = oidc.CodeHash("some-other-device-code")
		proof := signDPoPProof(t, key, jose.ES256, opts)

		result := deviceTokenRequest(t, deviceCode, proof).Result()
		body, _ := io.ReadAll(result.Body)
		assert.GreaterOrEqual(t, result.StatusCode, 400, string(body))
	})

	t.Run("proof without c_s256 is rejected", func(t *testing.T) {
		const deviceCode, userCode = "bound-nohash", "bound-nohash-user"
		completeBoundDeviceAuthorization(t, deviceCode, userCode, jkt, scopes)

		opts := defaultDPoPProofOpts()
		opts.htu = deviceTokenHTU
		proof := signDPoPProof(t, key, jose.ES256, opts)

		result := deviceTokenRequest(t, deviceCode, proof).Result()
		body, _ := io.ReadAll(result.Body)
		assert.GreaterOrEqual(t, result.StatusCode, 400, string(body))
	})

	t.Run("bound_key without a persisted jkt fails closed", func(t *testing.T) {
		const deviceCode, userCode = "bound-nojkt", "bound-nojkt-user"
		s := testProvider.Storage().(*storage.Storage)
		// Simulates a storage that dropped the thumbprint.
		require.NoError(t, s.StoreDeviceAuthorization(
			context.Background(), "native", deviceCode, userCode, time.Now().Add(time.Minute), scopes))
		require.NoError(t, s.CompleteDeviceAuthorization(context.Background(), userCode, "id1"))

		opts := defaultDPoPProofOpts()
		opts.htu = deviceTokenHTU
		opts.codeHash = oidc.CodeHash(deviceCode)
		proof := signDPoPProof(t, key, jose.ES256, opts)

		result := deviceTokenRequest(t, deviceCode, proof).Result()
		body, _ := io.ReadAll(result.Body)
		assert.GreaterOrEqual(t, result.StatusCode, 400, string(body))
		assert.Contains(t, string(body), string(oidc.ServerError))
	})

	t.Run("unbound device flow still ignores a DPoP header", func(t *testing.T) {
		const deviceCode, userCode = "unbound-dpop", "unbound-dpop-user"
		s := testProvider.Storage().(*storage.Storage)
		require.NoError(t, s.StoreDeviceAuthorization(
			context.Background(), "native", deviceCode, userCode, time.Now().Add(time.Minute), []string{oidc.ScopeOpenID}))
		require.NoError(t, s.CompleteDeviceAuthorization(context.Background(), userCode, "id1"))

		opts := defaultDPoPProofOpts()
		opts.htu = deviceTokenHTU
		proof := signDPoPProof(t, key, jose.ES256, opts)

		result := deviceTokenRequest(t, deviceCode, proof).Result()
		body, _ := io.ReadAll(result.Body)
		require.Less(t, result.StatusCode, 300, string(body))

		var response oidc.AccessTokenResponse
		require.NoError(t, json.Unmarshal(body, &response))
		require.NotEmpty(t, response.IDToken)

		signed, err := jose.ParseSigned(response.IDToken, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		typ, _ := signed.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string)
		assert.Equal(t, string(oidc.IDTokenTypeJWT), typ)

		var claims oidc.IDTokenClaims
		require.NoError(t, json.Unmarshal(signed.UnsafePayloadWithoutVerification(), &claims))
		assert.Nil(t, claims.Confirmation)
	})
}

func TestValidateDeviceAuthReqBoundKey(t *testing.T) {
	const validJKT = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"
	client, err := testProvider.Storage().GetClientByClientID(
		op.ContextWithIssuer(t.Context(), testIssuer), "native")
	require.NoError(t, err)

	tests := []struct {
		name       string
		request    *oidc.DeviceAuthorizationRequest
		wantErr    bool
		wantJKT    string
		wantScopes []string
	}{
		{
			name:       "no key binding is untouched",
			request:    &oidc.DeviceAuthorizationRequest{Scopes: []string{oidc.ScopeOpenID}},
			wantScopes: []string{oidc.ScopeOpenID},
		},
		{
			// dpop_jkt is also a plain RFC 9449 parameter, so it is ignored
			// rather than rejected when bound_key was not requested.
			name:       "dpop_jkt without bound_key is cleared",
			request:    &oidc.DeviceAuthorizationRequest{Scopes: []string{oidc.ScopeOpenID}, DPoPJKT: validJKT},
			wantScopes: []string{oidc.ScopeOpenID},
		},
		{
			name:       "valid bound_key request",
			request:    &oidc.DeviceAuthorizationRequest{Scopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, DPoPJKT: validJKT},
			wantJKT:    validJKT,
			wantScopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey},
		},
		{
			name:    "bound_key without dpop_jkt",
			request: &oidc.DeviceAuthorizationRequest{Scopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}},
			wantErr: true,
		},
		{
			name:    "bound_key without openid",
			request: &oidc.DeviceAuthorizationRequest{Scopes: []string{oidc.ScopeBoundKey}, DPoPJKT: validJKT},
			wantErr: true,
		},
		{
			name:    "malformed dpop_jkt",
			request: &oidc.DeviceAuthorizationRequest{Scopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, DPoPJKT: "not-a-thumbprint"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.ValidateDeviceAuthReqBoundKey(tt.request, client)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantJKT, tt.request.DPoPJKT)
			assert.Equal(t, oidc.SpaceDelimitedArray(tt.wantScopes), tt.request.Scopes)
		})
	}
}

// legacyDeviceStorage delegates everything to the example storage but embeds the
// op.Storage *interface*, so StoreBoundKeyDeviceAuthorization is not promoted and
// the type does not satisfy op.BoundKeyDeviceAuthorizationStorage. This models an
// OP written before key binding existed.
type legacyDeviceStorage struct {
	op.Storage
	inner *storage.Storage

	storedScopes []string
	storedBound  bool
}

func (s *legacyDeviceStorage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	s.storedScopes = scopes
	return s.inner.StoreDeviceAuthorization(ctx, clientID, deviceCode, userCode, expires, scopes)
}

func (s *legacyDeviceStorage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	return s.inner.GetDeviceAuthorizatonState(ctx, clientID, deviceCode)
}

// TestDeviceAuthorizationLegacyStorageIgnoresBoundKey is the device-flow
// counterpart to TestLegacyStorageCannotBreakOnBoundKey.
//
// A storage that predates key binding cannot persist dpop_jkt. Such a request
// must be downgraded to an ordinary unbound authorization rather than erroring,
// because `bound_key` is granted through Client.IsScopeAllowed and a permissive
// implementation may allow scopes it knows nothing about.
func TestDeviceAuthorizationLegacyStorageIgnoresBoundKey(t *testing.T) {
	inner := storage.NewStorage(storage.NewUserStore(testIssuer))
	legacy := &legacyDeviceStorage{Storage: inner, inner: inner}

	// Confirm the premise before relying on it.
	_, isBoundKeyStorage := any(legacy).(op.BoundKeyDeviceAuthorizationStorage)
	require.False(t, isBoundKeyStorage)
	require.True(t, testProvider.GrantTypeDeviceCodeSupported())

	keySet := &op.OpenIDKeySet{inner}
	provider, err := op.NewOpenIDProvider(testIssuer, testConfig, legacy,
		op.WithAllowInsecure(),
		op.WithAccessTokenKeySet(keySet),
		op.WithIDTokenHintKeySet(keySet),
	)
	require.NoError(t, err)

	// WithKeyBinding must refuse this storage outright, which is why the
	// downgrade below can only ever affect an OP that never enabled the feature.
	_, err = op.NewOpenIDProvider(testIssuer, testConfig, legacy,
		op.WithAllowInsecure(), op.WithKeyBinding())
	require.Error(t, err)

	body := url.Values{
		"scope":    {strings.Join([]string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, " ")},
		"dpop_jkt": {"HGRKq9Y6xVSVKQ8FZ4v0aX8Wd0lPqmB1Vv2FVQz7hIY"},
	}
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("device", "secret")
	w := httptest.NewRecorder()

	op.DeviceAuthorizationHandler(provider)(w, req)

	require.Equal(t, http.StatusOK, w.Code, "must not fail: %s", w.Body.String())
	var resp oidc.DeviceAuthorizationResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.DeviceCode)

	// bound_key must be stripped alongside dpop_jkt. Keeping the scope with an
	// empty thumbprint would look like a lost binding to requireBoundKeyConfirmation
	// (DeviceAuthorizationState always implements op.BoundKeyRequest) and would
	// fail closed at the token endpoint, merely relocating the error.
	assert.NotContains(t, legacy.storedScopes, oidc.ScopeBoundKey)
	assert.Contains(t, legacy.storedScopes, oidc.ScopeOpenID)

	state, err := legacy.GetDeviceAuthorizatonState(context.Background(), "device", resp.DeviceCode)
	require.NoError(t, err)
	assert.Empty(t, state.GetDPoPJKT())
	// With neither the scope nor a thumbprint this is an ordinary request, which
	// TestRequireBoundKeyConfirmation covers as the allowed "no scope, no jkt" case.
}

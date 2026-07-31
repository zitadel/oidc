package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/example/server/exampleop"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestNativeKeyBinding(t *testing.T) {
	for _, wrapServer := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_server=%t", wrapServer), func(t *testing.T) {
			testNativeKeyBinding(t, wrapServer)
		})
	}
}

func testNativeKeyBinding(t *testing.T, wrapServer bool) {
	ctx := context.Background()
	exampleStorage := storage.NewStorage(storage.NewUserStore("http://local-site"))
	var deferred deferredHandler
	opServer := httptest.NewServer(&deferred)
	defer opServer.Close()
	deferred.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, wrapServer)

	clientID := "key-binding-" + uuid.NewString()
	const clientSecret = "secret"
	const redirectURI = "http://local-site/callback"
	storage.RegisterClients(storage.WebClient(clientID, clientSecret, redirectURI))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jkt, err := oidc.JWKThumbprint(&jose.JSONWebKey{Key: &key.PublicKey})
	require.NoError(t, err)
	provider, err := rp.NewRelyingPartyOIDC(
		ctx,
		opServer.URL,
		clientID,
		clientSecret,
		redirectURI,
		[]string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
		rp.WithKeyBinding(key, jose.ES256),
	)
	require.NoError(t, err)

	issuerCtx := op.ContextWithIssuer(ctx, opServer.URL)
	authorizationURL, err := url.Parse(rp.AuthURL("state", provider))
	require.NoError(t, err)
	query := authorizationURL.Query()
	assert.Equal(t, jkt, query.Get(oidc.DPoPJKTParam))
	assert.Contains(t, query.Get("scope"), oidc.ScopeBoundKey)
	authClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authResponse, err := authClient.Get(authorizationURL.String())
	require.NoError(t, err)
	defer authResponse.Body.Close()
	require.Equal(t, http.StatusFound, authResponse.StatusCode)
	loginURL, err := authResponse.Location()
	require.NoError(t, err)
	authRequestID := loginURL.Query().Get("authRequestID")
	require.NotEmpty(t, authRequestID)
	authRequest, err := exampleStorage.AuthRequestByID(issuerCtx, authRequestID)
	require.NoError(t, err)
	boundRequest, ok := authRequest.(op.BoundKeyRequest)
	require.True(t, ok)
	assert.Equal(t, jkt, boundRequest.GetDPoPJKT())
	require.NoError(t, exampleStorage.CheckUsernamePassword("test-user@local-site", "verysecure", authRequest.GetID()))
	code := uuid.NewString()
	require.NoError(t, exampleStorage.SaveAuthCode(issuerCtx, authRequest.GetID(), code))
	plainProvider, err := rp.NewRelyingPartyOIDC(
		ctx,
		opServer.URL,
		clientID,
		clientSecret,
		redirectURI,
		[]string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
	)
	require.NoError(t, err)
	_, err = rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, plainProvider)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_dpop_proof")

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, provider)
	require.NoError(t, err)
	require.NotNil(t, tokens.IDTokenClaims.Confirmation)
	assertConfirmationThumbprint(t, tokens.IDTokenClaims.Confirmation, jkt)
	assertIDTokenType(t, tokens.IDToken, oidc.IDTokenTypeDPoP)
	require.NotEmpty(t, tokens.RefreshToken)

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongKeyProvider, err := rp.NewRelyingPartyOIDC(
		ctx,
		opServer.URL,
		clientID,
		clientSecret,
		redirectURI,
		[]string{oidc.ScopeOpenID},
		rp.WithKeyBinding(wrongKey, jose.ES256),
	)
	require.NoError(t, err)
	_, err = rp.RefreshTokens[*oidc.IDTokenClaims](ctx, wrongKeyProvider, tokens.RefreshToken, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_dpop_proof")

	refreshed, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, provider, tokens.RefreshToken, "", "")
	require.NoError(t, err)
	require.NotNil(t, refreshed.IDTokenClaims.Confirmation)
	assertConfirmationThumbprint(t, refreshed.IDTokenClaims.Confirmation, jkt)
	assertIDTokenType(t, refreshed.IDToken, oidc.IDTokenTypeDPoP)

	unboundRequest, err := exampleStorage.CreateAuthRequest(issuerCtx, &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: oidc.ResponseTypeCode,
	}, "id1")
	require.NoError(t, err)
	require.NoError(t, exampleStorage.AuthRequestDone(unboundRequest.GetID()))
	unboundCode := uuid.NewString()
	require.NoError(t, exampleStorage.SaveAuthCode(issuerCtx, unboundRequest.GetID(), unboundCode))
	unboundTokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, unboundCode, plainProvider)
	require.NoError(t, err)
	assert.Nil(t, unboundTokens.IDTokenClaims.Confirmation)
	assertIDTokenType(t, unboundTokens.IDToken, "JWT")
}

func assertConfirmationThumbprint(t *testing.T, confirmation *oidc.Confirmation, want string) {
	t.Helper()
	var jwk jose.JSONWebKey
	require.NoError(t, json.Unmarshal(confirmation.JWK, &jwk))
	got, err := oidc.JWKThumbprint(&jwk)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func assertIDTokenType(t *testing.T, token string, want jose.ContentType) {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, jws.Signatures, 1)
	assert.Equal(t, string(want), jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType])
}

// devicePollInterval must be long enough for a local HTTP round trip, because
// PollDeviceAccessTokenEndpoint uses it as the per-request timeout too.
const devicePollInterval = 200 * time.Millisecond

// TestNativeKeyBindingDeviceFlow exercises OpenID Connect Key Binding 1.0
// Section 3 end-to-end over the real HTTP stack, for both router modes (which
// covers the classic op.DeviceAccessToken handler and LegacyServer.DeviceToken).
func TestNativeKeyBindingDeviceFlow(t *testing.T) {
	for _, wrapServer := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_server=%t", wrapServer), func(t *testing.T) {
			testNativeKeyBindingDeviceFlow(t, wrapServer)
		})
	}
}

func testNativeKeyBindingDeviceFlow(t *testing.T, wrapServer bool) {
	ctx := context.Background()
	exampleStorage := storage.NewStorage(storage.NewUserStore("http://local-site"))
	var deferred deferredHandler
	opServer := httptest.NewServer(&deferred)
	defer opServer.Close()
	deferred.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, wrapServer)

	clientID := "key-binding-device-" + uuid.NewString()
	const clientSecret = "secret"
	storage.RegisterClients(storage.DeviceClient(clientID, clientSecret))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jkt, err := oidc.JWKThumbprint(&jose.JSONWebKey{Key: &key.PublicKey})
	require.NoError(t, err)

	// DeviceClient authenticates with Basic, so the RP must use AuthStyleInHeader.
	newProvider := func(opts ...rp.Option) rp.RelyingParty {
		provider, err := rp.NewRelyingPartyOIDC(ctx, opServer.URL, clientID, clientSecret, "",
			[]string{oidc.ScopeOpenID}, append([]rp.Option{
				rp.WithAuthStyle(oauth2.AuthStyleInHeader),
			}, opts...)...)
		require.NoError(t, err)
		return provider
	}
	provider := newProvider(rp.WithKeyBinding(key, jose.ES256))

	// Section 3.1: the device authorization request carries bound_key + dpop_jkt.
	deviceAuth, err := rp.DeviceAuthorization(ctx, []string{oidc.ScopeOpenID}, provider, nil)
	require.NoError(t, err)
	require.NotEmpty(t, deviceAuth.DeviceCode)
	require.NotEmpty(t, deviceAuth.UserCode)

	issuerCtx := op.ContextWithIssuer(ctx, opServer.URL)
	state, err := exampleStorage.GetDeviceAuthorizatonState(issuerCtx, clientID, deviceAuth.DeviceCode)
	require.NoError(t, err)
	assert.Equal(t, jkt, state.GetDPoPJKT(), "the OP must persist the committed thumbprint")
	assert.Contains(t, state.GetScopes(), oidc.ScopeBoundKey)

	require.NoError(t, exampleStorage.CompleteDeviceAuthorization(issuerCtx, deviceAuth.UserCode, "id1"))

	// An RP without the binding key cannot redeem the bound device code.
	_, err = rp.DeviceAccessToken(ctx, deviceAuth.DeviceCode, devicePollInterval, newProvider())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_dpop_proof")

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = rp.DeviceAccessToken(ctx, deviceAuth.DeviceCode, devicePollInterval,
		newProvider(rp.WithKeyBinding(wrongKey, jose.ES256)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_dpop_proof")

	// Section 3.3: the correct key yields a key-bound ID Token.
	tokens, err := rp.DeviceAccessToken(ctx, deviceAuth.DeviceCode, devicePollInterval, provider)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.IDToken)
	assertIDTokenType(t, tokens.IDToken, oidc.IDTokenTypeDPoP)

	var claims oidc.IDTokenClaims
	require.NoError(t, json.Unmarshal(unsafeIDTokenPayload(t, tokens.IDToken), &claims))
	require.NotNil(t, claims.Confirmation)
	assertConfirmationThumbprint(t, claims.Confirmation, jkt)
}

// TestNativeKeyBindingDeviceFlowUnbound ensures the device flow is unchanged
// when key binding is not configured.
func TestNativeKeyBindingDeviceFlowUnbound(t *testing.T) {
	ctx := context.Background()
	exampleStorage := storage.NewStorage(storage.NewUserStore("http://local-site"))
	var deferred deferredHandler
	opServer := httptest.NewServer(&deferred)
	defer opServer.Close()
	deferred.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, false)

	clientID := "device-unbound-" + uuid.NewString()
	const clientSecret = "secret"
	storage.RegisterClients(storage.DeviceClient(clientID, clientSecret))

	provider, err := rp.NewRelyingPartyOIDC(ctx, opServer.URL, clientID, clientSecret, "",
		[]string{oidc.ScopeOpenID}, rp.WithAuthStyle(oauth2.AuthStyleInHeader))
	require.NoError(t, err)

	deviceAuth, err := rp.DeviceAuthorization(ctx, []string{oidc.ScopeOpenID}, provider, nil)
	require.NoError(t, err)

	issuerCtx := op.ContextWithIssuer(ctx, opServer.URL)
	state, err := exampleStorage.GetDeviceAuthorizatonState(issuerCtx, clientID, deviceAuth.DeviceCode)
	require.NoError(t, err)
	assert.Empty(t, state.GetDPoPJKT())
	assert.NotContains(t, state.GetScopes(), oidc.ScopeBoundKey)

	require.NoError(t, exampleStorage.CompleteDeviceAuthorization(issuerCtx, deviceAuth.UserCode, "id1"))

	tokens, err := rp.DeviceAccessToken(ctx, deviceAuth.DeviceCode, devicePollInterval, provider)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.IDToken)
	assertIDTokenType(t, tokens.IDToken, oidc.IDTokenTypeJWT)

	var claims oidc.IDTokenClaims
	require.NoError(t, json.Unmarshal(unsafeIDTokenPayload(t, tokens.IDToken), &claims))
	assert.Nil(t, claims.Confirmation)
}

func unsafeIDTokenPayload(t *testing.T, token string) []byte {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	return jws.UnsafePayloadWithoutVerification()
}

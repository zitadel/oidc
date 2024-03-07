package op_test

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

var (
	testProvider op.OpenIDProvider
	testConfig   = &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		DefaultLogoutRedirectURI: pathLoggedOut,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedClaims:          op.DefaultSupportedClaims,
		SupportedUILocales:       []language.Tag{language.English},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}
)

const (
	testIssuer    = "https://localhost:9998/"
	pathLoggedOut = "/logged-out"
)

func init() {
	storage.RegisterClients(
		storage.NativeClient("native"),
		storage.WebClient("web", "secret", "https://example.com"),
		storage.DeviceClient("device", "secret"),
		storage.WebClient("api", "secret"),
	)

	testProvider = newTestProvider(testConfig)
}

func newTestProvider(config *op.Config) op.OpenIDProvider {
	storage := storage.NewStorage(storage.NewUserStore(testIssuer))
	keySet := &op.OpenIDKeySet{storage}
	provider, err := op.NewOpenIDProvider(testIssuer, config, storage,
		op.WithAllowInsecure(),
		op.WithAccessTokenKeySet(keySet),
		op.WithIDTokenHintKeySet(keySet),
	)
	if err != nil {
		panic(err)
	}
	return provider
}

type routesTestStorage interface {
	op.Storage
	AuthRequestDone(id string) error
}

func mapAsValues(m map[string]string) string {
	values := make(url.Values, len(m))
	for k, v := range m {
		values.Set(k, v)
	}
	return values.Encode()
}

func TestRoutes(t *testing.T) {
	storage := testProvider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)

	client, err := storage.GetClientByClientID(ctx, "web")
	require.NoError(t, err)

	oidcAuthReq := &oidc.AuthRequest{
		ClientID:     client.GetID(),
		RedirectURI:  "https://example.com",
		MaxAge:       gu.Ptr[uint](300),
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, oidc.ScopeEmail, oidc.ScopeProfile, oidc.ScopePhone},
		ResponseType: oidc.ResponseTypeCode,
	}

	authReq, err := storage.CreateAuthRequest(ctx, oidcAuthReq, "id1")
	require.NoError(t, err)
	storage.AuthRequestDone(authReq.GetID())

	accessToken, refreshToken, _, err := op.CreateAccessToken(ctx, authReq, op.AccessTokenTypeBearer, testProvider, client, "")
	require.NoError(t, err)
	accessTokenRevoke, _, _, err := op.CreateAccessToken(ctx, authReq, op.AccessTokenTypeBearer, testProvider, client, "")
	require.NoError(t, err)
	idToken, err := op.CreateIDToken(ctx, testIssuer, authReq, time.Hour, accessToken, "123", storage, client)
	require.NoError(t, err)
	jwtToken, _, _, err := op.CreateAccessToken(ctx, authReq, op.AccessTokenTypeJWT, testProvider, client, "")
	require.NoError(t, err)

	oidcAuthReq.IDTokenHint = idToken

	serverURL, err := url.Parse(testIssuer)
	require.NoError(t, err)

	type basicAuth struct {
		username, password string
	}

	tests := []struct {
		name           string
		method         string
		path           string
		basicAuth      *basicAuth
		header         map[string]string
		values         map[string]string
		body           map[string]string
		wantCode       int
		headerContains map[string]string
		json           string   // test for exact json output
		contains       []string // when the body output is not constant, we just check for snippets to be present in the response
	}{
		{
			name:     "health",
			method:   http.MethodGet,
			path:     "/healthz",
			wantCode: http.StatusOK,
			json:     `{"status":"ok"}`,
		},
		{
			name:     "ready",
			method:   http.MethodGet,
			path:     "/ready",
			wantCode: http.StatusOK,
			json:     `{"status":"ok"}`,
		},
		{
			name:     "discovery",
			method:   http.MethodGet,
			path:     oidc.DiscoveryEndpoint,
			wantCode: http.StatusOK,
			json:     `{"issuer":"https://localhost:9998/","authorization_endpoint":"https://localhost:9998/authorize","token_endpoint":"https://localhost:9998/oauth/token","introspection_endpoint":"https://localhost:9998/oauth/introspect","userinfo_endpoint":"https://localhost:9998/userinfo","revocation_endpoint":"https://localhost:9998/revoke","end_session_endpoint":"https://localhost:9998/end_session","device_authorization_endpoint":"https://localhost:9998/device_authorization","jwks_uri":"https://localhost:9998/keys","scopes_supported":["openid","profile","email","phone","address","offline_access"],"response_types_supported":["code","id_token","id_token token"],"grant_types_supported":["authorization_code","implicit","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:jwt-bearer","urn:ietf:params:oauth:grant-type:device_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"request_object_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt"],"token_endpoint_auth_signing_alg_values_supported":["RS256"],"revocation_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post","private_key_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["RS256"],"introspection_endpoint_auth_methods_supported":["client_secret_basic","private_key_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["RS256"],"claims_supported":["sub","aud","exp","iat","iss","auth_time","nonce","acr","amr","c_hash","at_hash","act","scopes","client_id","azp","preferred_username","name","family_name","given_name","locale","email","email_verified","phone_number","phone_number_verified"],"code_challenge_methods_supported":["S256"],"ui_locales_supported":["en"],"request_parameter_supported":true,"request_uri_parameter_supported":false}`,
		},
		{
			name:   "authorization",
			method: http.MethodGet,
			path:   testProvider.AuthorizationEndpoint().Relative(),
			values: map[string]string{
				"client_id":     client.GetID(),
				"redirect_uri":  "https://example.com",
				"scope":         oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}.String(),
				"response_type": string(oidc.ResponseTypeCode),
			},
			wantCode:       http.StatusFound,
			headerContains: map[string]string{"Location": "/login/username?authRequestID="},
		},
		{
			name:           "authorization callback",
			method:         http.MethodGet,
			path:           testProvider.AuthorizationEndpoint().Relative() + "/callback",
			values:         map[string]string{"id": authReq.GetID()},
			wantCode:       http.StatusFound,
			headerContains: map[string]string{"Location": "https://example.com?code="},
			contains: []string{
				`<a href="https://example.com?code=`,
				">Found</a>.",
			},
		},
		{
			// This call will fail. A successful test is already
			// part of client/integration_test.go
			name:   "code exchange",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type": string(oidc.GrantTypeCode),
				"code":       "123",
			},
			wantCode: http.StatusUnauthorized,
			json:     `{"error":"invalid_client"}`,
		},
		{
			name:   "JWT authorization",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type": string(oidc.GrantTypeBearer),
				"scope":      oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}.String(),
				"assertion":  jwtToken,
			},
			wantCode: http.StatusBadRequest,
			json:     "{\"error\":\"server_error\",\"error_description\":\"audience is not valid: Audience must contain client_id \\\"https://localhost:9998/\\\"\"}",
		},
		{
			name:      "Token exchange",
			method:    http.MethodGet,
			path:      testProvider.TokenEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			values: map[string]string{
				"grant_type":         string(oidc.GrantTypeTokenExchange),
				"scope":              oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}.String(),
				"subject_token":      jwtToken,
				"subject_token_type": string(oidc.AccessTokenType),
			},
			wantCode: http.StatusOK,
			contains: []string{
				`{"access_token":"`,
				`","issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token","token_type":"Bearer","expires_in":299,"scope":"openid offline_access","refresh_token":"`,
			},
		},
		{
			name:      "Client credentials exchange",
			method:    http.MethodGet,
			path:      testProvider.TokenEndpoint().Relative(),
			basicAuth: &basicAuth{"sid1", "verysecret"},
			values: map[string]string{
				"grant_type": string(oidc.GrantTypeClientCredentials),
				"scope":      oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}.String(),
			},
			wantCode: http.StatusOK,
			contains: []string{`{"access_token":"`, `","token_type":"Bearer","expires_in":299}`},
		},
		{
			// This call will fail. A successful test is already
			// part of device_test.go
			name:      "device token",
			method:    http.MethodPost,
			path:      testProvider.TokenEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			header: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: map[string]string{
				"grant_type":  string(oidc.GrantTypeDeviceCode),
				"device_code": "123",
			},
			wantCode: http.StatusBadRequest,
			json:     `{"error":"access_denied","error_description":"The authorization request was denied."}`,
		},
		{
			name:     "missing grant type",
			method:   http.MethodGet,
			path:     testProvider.TokenEndpoint().Relative(),
			wantCode: http.StatusBadRequest,
			json:     `{"error":"invalid_request","error_description":"grant_type missing"}`,
		},
		{
			name:   "unsupported grant type",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type": "foo",
			},
			wantCode: http.StatusBadRequest,
			json:     `{"error":"unsupported_grant_type","error_description":"foo not supported"}`,
		},
		{
			name:      "introspection",
			method:    http.MethodGet,
			path:      testProvider.IntrospectionEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			values: map[string]string{
				"token": accessToken,
			},
			wantCode: http.StatusOK,
			json:     `{"active":true,"scope":"openid offline_access email profile phone","client_id":"web","sub":"id1","username":"test-user@localhost","name":"Test User","given_name":"Test","family_name":"User","locale":"de","preferred_username":"test-user@localhost","email":"test-user@zitadel.ch","email_verified":true}`,
		},
		{
			name:   "user info",
			method: http.MethodGet,
			path:   testProvider.UserinfoEndpoint().Relative(),
			header: map[string]string{
				"authorization": "Bearer " + accessToken,
			},
			wantCode: http.StatusOK,
			json:     `{"sub":"id1","name":"Test User","given_name":"Test","family_name":"User","locale":"de","preferred_username":"test-user@localhost","email":"test-user@zitadel.ch","email_verified":true}`,
		},
		{
			name:   "refresh token",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type":    string(oidc.GrantTypeRefreshToken),
				"refresh_token": refreshToken,
				"client_id":     client.GetID(),
				"client_secret": "secret",
			},
			wantCode: http.StatusOK,
			contains: []string{
				`{"access_token":"`,
				`","token_type":"Bearer","refresh_token":"`,
				`","expires_in":299,"id_token":"`,
			},
		},
		{
			name:      "revoke",
			method:    http.MethodGet,
			path:      testProvider.RevocationEndpoint().Relative(),
			basicAuth: &basicAuth{"web", "secret"},
			values: map[string]string{
				"token": accessTokenRevoke,
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "end session",
			method: http.MethodGet,
			path:   testProvider.EndSessionEndpoint().Relative(),
			values: map[string]string{
				"id_token_hint": idToken,
				"client_id":     "web",
			},
			wantCode:       http.StatusFound,
			headerContains: map[string]string{"Location": "/logged-out"},
			contains:       []string{`<a href="/logged-out">Found</a>.`},
		},
		{
			name:     "keys",
			method:   http.MethodGet,
			path:     testProvider.KeysEndpoint().Relative(),
			wantCode: http.StatusOK,
			contains: []string{
				`{"keys":[{"use":"sig","kty":"RSA","kid":"`,
				`","alg":"RS256","n":"`, `","e":"AQAB"}]}`,
			},
		},
		{
			name:      "device authorization",
			method:    http.MethodGet,
			path:      testProvider.DeviceAuthorizationEndpoint().Relative(),
			basicAuth: &basicAuth{"device", "secret"},
			values: map[string]string{
				"scope": oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}.String(),
			},
			wantCode: http.StatusOK,
			contains: []string{
				`{"device_code":"`, `","user_code":"`,
				`","verification_uri":"https://localhost:9998/device"`,
				`"verification_uri_complete":"https://localhost:9998/device?user_code=`,
				`","expires_in":300,"interval":5}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := gu.PtrCopy(serverURL)
			u.Path = tt.path
			if tt.values != nil {
				u.RawQuery = mapAsValues(tt.values)
			}
			var body io.Reader
			if tt.body != nil {
				body = strings.NewReader(mapAsValues(tt.body))
			}

			req := httptest.NewRequest(tt.method, u.String(), body)
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			if tt.basicAuth != nil {
				req.SetBasicAuth(tt.basicAuth.username, tt.basicAuth.password)
			}

			rec := httptest.NewRecorder()
			testProvider.ServeHTTP(rec, req)

			resp := rec.Result()
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, resp.StatusCode)

			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			respBodyString := string(respBody)
			t.Log(respBodyString)
			t.Log(resp.Header)

			if tt.json != "" {
				assert.JSONEq(t, tt.json, respBodyString)
			}
			for _, c := range tt.contains {
				assert.Contains(t, respBodyString, c)
			}
			for k, v := range tt.headerContains {
				assert.Contains(t, resp.Header.Get(k), v)
			}
		})
	}
}

func TestWithCustomEndpoints(t *testing.T) {
	type args struct {
		auth       *op.Endpoint
		token      *op.Endpoint
		userInfo   *op.Endpoint
		revocation *op.Endpoint
		endSession *op.Endpoint
		keys       *op.Endpoint
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "all nil",
			args:    args{},
			wantErr: op.ErrNilEndpoint,
		},
		{
			name: "all set",
			args: args{
				auth:       op.NewEndpoint("/authorize"),
				token:      op.NewEndpoint("/oauth/token"),
				userInfo:   op.NewEndpoint("/userinfo"),
				revocation: op.NewEndpoint("/revoke"),
				endSession: op.NewEndpoint("/end_session"),
				keys:       op.NewEndpoint("/keys"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := op.NewOpenIDProvider(testIssuer, testConfig,
				storage.NewStorage(storage.NewUserStore(testIssuer)),
				op.WithCustomEndpoints(tt.args.auth, tt.args.token, tt.args.userInfo, tt.args.revocation, tt.args.endSession, tt.args.keys),
			)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr != nil {
				return
			}
			assert.Equal(t, tt.args.auth, provider.AuthorizationEndpoint())
			assert.Equal(t, tt.args.token, provider.TokenEndpoint())
			assert.Equal(t, tt.args.userInfo, provider.UserinfoEndpoint())
			assert.Equal(t, tt.args.revocation, provider.RevocationEndpoint())
			assert.Equal(t, tt.args.endSession, provider.EndSessionEndpoint())
			assert.Equal(t, tt.args.keys, provider.KeysEndpoint())
		})
	}
}

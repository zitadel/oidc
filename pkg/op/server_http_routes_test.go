package op_test

import (
	"context"
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

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func jwtProfile() (string, error) {
	keyData, err := client.ConfigFromKeyFile("../../example/server/service-key1.json")
	if err != nil {
		return "", err
	}
	signer, err := client.NewSignerFromPrivateKeyByte([]byte(keyData.Key), keyData.KeyID)
	if err != nil {
		return "", err
	}
	return client.SignedJWTProfileAssertion(keyData.UserID, []string{testIssuer}, time.Hour, signer)
}

func TestServerRoutes(t *testing.T) {
	server := op.RegisterLegacyServer(op.NewLegacyServer(testProvider, *op.DefaultEndpoints), op.AuthorizeCallbackHandler(testProvider))

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
	jwtProfileToken, err := jwtProfile()
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
			// This call will fail. A successfull test is already
			// part of client/integration_test.go
			name:   "code exchange",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type":    string(oidc.GrantTypeCode),
				"client_id":     client.GetID(),
				"client_secret": "secret",
				"redirect_uri":  "https://example.com",
				"code":          "123",
			},
			wantCode: http.StatusBadRequest,
			json:     `{"error":"invalid_grant", "error_description":"invalid code"}`,
		},
		{
			name:   "JWT authorization",
			method: http.MethodGet,
			path:   testProvider.TokenEndpoint().Relative(),
			values: map[string]string{
				"grant_type": string(oidc.GrantTypeBearer),
				"scope":      oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}.String(),
				"assertion":  jwtProfileToken,
			},
			wantCode: http.StatusOK,
			contains: []string{`{"access_token":`, `"token_type":"Bearer","expires_in":299}`},
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
			basicAuth: &basicAuth{"device", "secret"},
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
			server.ServeHTTP(rec, req)

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

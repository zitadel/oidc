package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v4/example/server/storage"
	"github.com/zitadel/oidc/v4/pkg/client"
	"github.com/zitadel/oidc/v4/pkg/oidc"
	"github.com/zitadel/oidc/v4/pkg/op"
)

const (
	failAuthorizeClientIDSecret = "AuthorizeClientIDSecret"
	failClientCredentials       = "ClientCredentials"
	failGetClientByClientID     = "GetClientByClientID"
	failGetKeyByIDAndClientID   = "GetKeyByIDAndClientID"
)

// failingClientStorage wraps the example storage and fails the client
// authentication lookup named by method with err.
type failingClientStorage struct {
	*storage.Storage
	method string
	err    error
}

func (s *failingClientStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	if s.method == failAuthorizeClientIDSecret {
		return s.err
	}
	return s.Storage.AuthorizeClientIDSecret(ctx, clientID, clientSecret)
}

func (s *failingClientStorage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	if s.method == failClientCredentials {
		return nil, s.err
	}
	return s.Storage.ClientCredentials(ctx, clientID, clientSecret)
}

func (s *failingClientStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	if s.method == failGetClientByClientID {
		return nil, s.err
	}
	return s.Storage.GetClientByClientID(ctx, clientID)
}

func (s *failingClientStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	if s.method == failGetKeyByIDAndClientID {
		return nil, s.err
	}
	return s.Storage.GetKeyByIDAndClientID(ctx, keyID, clientID)
}

// clientAuthAnswer is the response a handler gives for a client
// authentication failure that is not a server_error.
type clientAuthAnswer struct {
	errorType string
	status    int
}

func TestClientAuthStorageErrors(t *testing.T) {
	// One storage for all subtests, so that the RSA key is generated once.
	s := storage.NewStorage(storage.NewUserStore(testIssuer))

	// A valid code, so that the Provider's code flow reaches client authentication.
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "web",
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: oidc.ResponseTypeCode,
	}, "id1")
	require.NoError(t, err)
	const code = "client-auth-storage-errors"
	require.NoError(t, s.SaveAuthCode(ctx, authReq.GetID(), code))
	require.NoError(t, s.AuthRequestDone(authReq.GetID()))

	codeForm := url.Values{
		"grant_type":   {string(oidc.GrantTypeCode)},
		"code":         {code},
		"redirect_uri": {"https://example.com"},
	}
	// A valid assertion, so that private_key_jwt reaches the key and client lookups.
	assertion, err := jwtProfile()
	require.NoError(t, err)
	jwtCodeForm := url.Values{
		"grant_type":            {string(oidc.GrantTypeCode)},
		"code":                  {code},
		"redirect_uri":          {"https://example.com"},
		"client_assertion":      {assertion},
		"client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
	}
	invalidClient := map[string]clientAuthAnswer{
		"Provider":  {string(oidc.InvalidClient), http.StatusUnauthorized},
		"op.Server": {string(oidc.InvalidClient), http.StatusUnauthorized},
	}

	requests := []struct {
		name     string
		method   string
		endpoint func(op.OpenIDProvider) *op.Endpoint
		form     url.Values
		// basicAuth sends web:secret in the Authorization header,
		// otherwise the form carries the client credentials.
		basicAuth bool
		// want lists the handlers to test, by authorizePath name.
		want map[string]clientAuthAnswer
	}{
		{
			name:      "token client_credentials",
			method:    failClientCredentials,
			endpoint:  op.OpenIDProvider.TokenEndpoint,
			form:      url.Values{"grant_type": {string(oidc.GrantTypeClientCredentials)}, "scope": {oidc.ScopeOpenID}},
			basicAuth: true,
			want:      invalidClient,
		},
		{
			name:     "token private_key_jwt key lookup",
			method:   failGetKeyByIDAndClientID,
			endpoint: op.OpenIDProvider.TokenEndpoint,
			form:     jwtCodeForm,
			want:     invalidClient,
		},
		{
			name:     "token private_key_jwt client lookup",
			method:   failGetClientByClientID,
			endpoint: op.OpenIDProvider.TokenEndpoint,
			form:     jwtCodeForm,
			want:     invalidClient,
		},
		{
			name:      "token authorization_code client lookup",
			method:    failGetClientByClientID,
			endpoint:  op.OpenIDProvider.TokenEndpoint,
			form:      codeForm,
			basicAuth: true,
			want:      invalidClient,
		},
		{
			name:      "token authorization_code secret check",
			method:    failAuthorizeClientIDSecret,
			endpoint:  op.OpenIDProvider.TokenEndpoint,
			form:      codeForm,
			basicAuth: true,
			want:      invalidClient,
		},
		{
			name:     "token token_exchange client lookup",
			method:   failGetClientByClientID,
			endpoint: op.OpenIDProvider.TokenEndpoint,
			form: url.Values{
				"grant_type":         {string(oidc.GrantTypeTokenExchange)},
				"subject_token":      {"token"},
				"subject_token_type": {string(oidc.AccessTokenType)},
			},
			basicAuth: true,
			want:      invalidClient,
		},
		{
			name:     "revocation client lookup",
			method:   failGetClientByClientID,
			endpoint: op.OpenIDProvider.RevocationEndpoint,
			form:     url.Values{"token": {"token"}, "client_id": {"web"}, "client_secret": {"secret"}},
			want:     invalidClient,
		},
		{
			name:      "introspection secret check",
			method:    failAuthorizeClientIDSecret,
			endpoint:  op.OpenIDProvider.IntrospectionEndpoint,
			form:      url.Values{"token": {"token"}},
			basicAuth: true,
			// The Provider introspection handler answers every error with 401.
			want: map[string]clientAuthAnswer{"op.Server": invalidClient["op.Server"]},
		},
	}

	dbErr := errors.New("db down")
	storageErrors := []struct {
		name string
		err  error
		// serverError is true when the answer must be a server_error.
		serverError bool
		// legacyStatus overrides the 500 of a server_error on the LegacyServer.
		legacyStatus int
	}{
		{
			name:        "server_error",
			err:         oidc.ErrServerError().WithParent(dbErr),
			serverError: true,
		},
		{
			name:        "server_error returning a nil parent",
			err:         oidc.ErrServerError().WithReturnParentToClient(true),
			serverError: true,
		},
		{
			name:         "server_error with status 503",
			err:          op.NewStatusError(oidc.ErrServerError().WithParent(dbErr), http.StatusServiceUnavailable),
			serverError:  true,
			legacyStatus: http.StatusServiceUnavailable,
		},
		{
			name:        "context deadline",
			err:         fmt.Errorf("lookup: %w", context.DeadlineExceeded),
			serverError: true,
		},
		{
			name: "plain error",
			err:  errors.New("client not found"),
		},
		{
			name: "typed client error",
			err:  oidc.ErrInvalidRequest().WithDescription("rejected by storage"),
		},
	}

	for _, req := range requests {
		for _, se := range storageErrors {
			fs := &failingClientStorage{Storage: s, method: req.method, err: se.err}
			provider, err := op.NewProvider(testConfig, fs, op.StaticIssuer(testIssuer), op.WithAllowInsecure())
			require.NoError(t, err)

			for _, path := range authorizePaths(provider) {
				want, ok := req.want[path.name]
				if !ok {
					continue
				}
				if se.serverError {
					want = clientAuthAnswer{string(oidc.ServerError), http.StatusInternalServerError}
					if path.name == "op.Server" && se.legacyStatus != 0 {
						want.status = se.legacyStatus
					}
				}
				t.Run(path.name+"/"+req.name+"/"+se.name, func(t *testing.T) {
					r := httptest.NewRequest(http.MethodPost, req.endpoint(provider).Relative(), strings.NewReader(req.form.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					if req.basicAuth {
						r.SetBasicAuth("web", "secret")
					}
					rec := httptest.NewRecorder()
					path.handler.ServeHTTP(rec, r)

					var body map[string]any
					require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
					assert.Equal(t, want.status, rec.Code, rec.Body.String())
					assert.Equal(t, want.errorType, body["error"], rec.Body.String())
					assert.NotContains(t, body, "parent", rec.Body.String())
				})
			}
		}
	}
}

// TestClientAuthInvalidClient sends failed client authentications to the
// stock LegacyServer and the Provider with the example storage, so that it
// catches an error from the storage or the handlers that is not invalid_client.
func TestClientAuthInvalidClient(t *testing.T) {
	s := storage.NewStorage(storage.NewUserStore(testIssuer))
	provider, err := op.NewProvider(testConfig, s, op.StaticIssuer(testIssuer), op.WithAllowInsecure())
	require.NoError(t, err)
	handler := op.RegisterLegacyServer(op.NewLegacyServer(provider, *op.DefaultEndpoints), op.AuthorizeCallbackHandler(provider))

	// A valid code, so that the Provider's code flow reaches client authentication.
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "web",
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: oidc.ResponseTypeCode,
	}, "id1")
	require.NoError(t, err)
	const code = "client-auth-invalid-client"
	require.NoError(t, s.SaveAuthCode(ctx, authReq.GetID(), code))
	require.NoError(t, s.AuthRequestDone(authReq.GetID()))

	key, err := os.ReadFile("../../example/server/service-key1.pem")
	require.NoError(t, err)
	signer, err := client.NewSignerFromPrivateKeyByte(key, storage.ServiceUserKeyID)
	require.NoError(t, err)
	wrongAudience, err := client.SignedJWTProfileAssertion(storage.ServiceUserID, []string{"https://other.example"}, time.Hour, signer)
	require.NoError(t, err)
	// The example storage has a key for this issuer, but no client.
	unknownClient, err := jwtProfile()
	require.NoError(t, err)

	codeGrant := func(assertion string) url.Values {
		return url.Values{
			"grant_type":            {string(oidc.GrantTypeCode)},
			"code":                  {code},
			"redirect_uri":          {"https://example.com"},
			"client_assertion":      {assertion},
			"client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
		}
	}
	tests := []struct {
		name     string
		endpoint *op.Endpoint
		form     url.Values
		// user and password go in the Authorization header, unless user is empty.
		user, password string
		description    string
		// provider sends the request to the Provider, which sends no WWW-Authenticate header.
		provider bool
	}{
		{
			name:     "introspection Basic wrong secret",
			endpoint: provider.IntrospectionEndpoint(),
			form:     url.Values{"token": {"abc"}},
			user:     "web",
			password: "wrong",
		},
		{
			name:     "introspection Basic unknown client",
			endpoint: provider.IntrospectionEndpoint(),
			form:     url.Values{"token": {"abc"}},
			user:     "nobody",
			password: "secret",
		},
		{
			name:     "introspection bad client_assertion",
			endpoint: provider.IntrospectionEndpoint(),
			form: url.Values{
				"token":                 {"abc"},
				"client_assertion":      {"abc"},
				"client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
			},
			description: "JWT assertion failed",
		},
		{
			name:        "token malformed private_key_jwt assertion",
			endpoint:    provider.TokenEndpoint(),
			form:        codeGrant("abc"),
			description: "JWT assertion failed",
		},
		{
			name:        "token private_key_jwt assertion for another audience",
			endpoint:    provider.TokenEndpoint(),
			form:        codeGrant(wrongAudience),
			description: "JWT assertion failed",
		},
		{
			name:     "token private_key_jwt assertion of an unknown client",
			endpoint: provider.TokenEndpoint(),
			form:     codeGrant(unknownClient),
		},
		{
			name:     "token client_credentials wrong secret",
			endpoint: provider.TokenEndpoint(),
			form:     url.Values{"grant_type": {string(oidc.GrantTypeClientCredentials)}, "scope": {oidc.ScopeOpenID}},
			user:     "sid1",
			password: "wrong",
		},
		{
			name:     "Provider device authorization Basic wrong secret",
			endpoint: provider.DeviceAuthorizationEndpoint(),
			form:     url.Values{"scope": {oidc.ScopeOpenID}},
			user:     "device",
			password: "wrong",
			provider: true,
		},
		{
			name:        "Provider token malformed private_key_jwt assertion",
			endpoint:    provider.TokenEndpoint(),
			form:        codeGrant("abc"),
			description: "JWT assertion failed",
			provider:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tt.endpoint.Relative(), strings.NewReader(tt.form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.user != "" {
				r.SetBasicAuth(tt.user, tt.password)
			}
			rec := httptest.NewRecorder()
			wantAuthenticate := `Basic realm="oauth"`
			if tt.provider {
				provider.ServeHTTP(rec, r)
				wantAuthenticate = ""
			} else {
				handler.ServeHTTP(rec, r)
			}

			var body map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
			assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			assert.Equal(t, string(oidc.InvalidClient), body["error"], rec.Body.String())
			description, _ := body["error_description"].(string)
			assert.Equal(t, tt.description, description, rec.Body.String())
			assert.Equal(t, wantAuthenticate, rec.Header().Get("WWW-Authenticate"))
		})
	}
}

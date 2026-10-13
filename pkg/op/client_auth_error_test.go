package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	failAuthorizeClientIDSecret = "AuthorizeClientIDSecret"
	failClientCredentials       = "ClientCredentials"
	failGetClientByClientID     = "GetClientByClientID"
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
	invalidClient := map[string]clientAuthAnswer{
		"Provider":  {string(oidc.InvalidClient), http.StatusUnauthorized},
		"op.Server": {string(oidc.InvalidClient), http.StatusBadRequest},
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
			// The LegacyServer returns the ClientCredentials error as is.
			want: map[string]clientAuthAnswer{"Provider": invalidClient["Provider"]},
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
			want: map[string]clientAuthAnswer{"op.Server": {string(oidc.UnauthorizedClient), http.StatusBadRequest}},
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
			provider, err := op.NewOpenIDProvider(testIssuer, testConfig, fs, op.WithAllowInsecure())
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

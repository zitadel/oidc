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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
)

var clientAuthStorageErrorTests = []struct {
	name       string
	storageErr error
	wantType   string
	wantStatus int
}{
	{
		name:       "typed server_error passes through",
		storageErr: oidc.ErrServerError().WithParent(errors.New("db down")),
		wantType:   string(oidc.ServerError),
		wantStatus: http.StatusInternalServerError,
	},
	{
		name:       "plain error stays invalid_client",
		storageErr: errors.New("client not found"),
		wantType:   string(oidc.InvalidClient),
		wantStatus: http.StatusUnauthorized,
	},
}

type clientCredentialsErrorStorage struct {
	err error
}

func (s clientCredentialsErrorStorage) ClientCredentials(context.Context, string, string) (op.Client, error) {
	return nil, s.err
}

func (s clientCredentialsErrorStorage) ClientCredentialsTokenRequest(context.Context, string, []string) (op.TokenRequest, error) {
	return nil, errors.New("not reached")
}

func TestAuthorizeClientCredentialsClient_StorageErrors(t *testing.T) {
	for _, tt := range clientAuthStorageErrorTests {
		t.Run(tt.name, func(t *testing.T) {
			req := &oidc.ClientCredentialsRequest{ClientID: "id", ClientSecret: "secret"}
			_, err := op.AuthorizeClientCredentialsClient(context.Background(), req, clientCredentialsErrorStorage{err: tt.storageErr})
			var oidcErr *oidc.Error
			require.ErrorAs(t, err, &oidcErr)
			assert.Equal(t, tt.wantType, string(oidcErr.ErrorType))
		})
	}
}

func TestAuthorizeClientIDSecret_StorageErrors(t *testing.T) {
	for _, tt := range clientAuthStorageErrorTests {
		t.Run(tt.name, func(t *testing.T) {
			s := mock.NewMockStorage(gomock.NewController(t))
			s.EXPECT().AuthorizeClientIDSecret(gomock.Any(), "id", "secret").Return(tt.storageErr)
			err := op.AuthorizeClientIDSecret(context.Background(), "id", "secret", s)
			var oidcErr *oidc.Error
			require.ErrorAs(t, err, &oidcErr)
			assert.Equal(t, tt.wantType, string(oidcErr.ErrorType))
		})
	}
}

// failingClientStorage wraps the example storage and fails the client
// authentication lookups with a configurable error.
type failingClientStorage struct {
	*storage.Storage
	err error
}

func (s *failingClientStorage) AuthorizeClientIDSecret(context.Context, string, string) error {
	return s.err
}

func (s *failingClientStorage) ClientCredentials(context.Context, string, string) (op.Client, error) {
	return nil, s.err
}

func TestTokenEndpoint_ClientAuthStorageErrors(t *testing.T) {
	grants := []struct {
		name     string
		clientID string
		secret   string
		form     url.Values
	}{
		{
			name:     "client_credentials",
			clientID: "sid1",
			secret:   "verysecret",
			form:     url.Values{"grant_type": {string(oidc.GrantTypeClientCredentials)}, "scope": {"openid"}},
		},
		{
			name:     "authorization_code",
			clientID: "web",
			secret:   "secret",
			form: url.Values{
				"grant_type":   {string(oidc.GrantTypeCode)},
				"code":         {"code"},
				"redirect_uri": {"https://example.com"},
			},
		},
	}
	for _, g := range grants {
		for _, tt := range clientAuthStorageErrorTests {
			t.Run(g.name+"/"+tt.name, func(t *testing.T) {
				s := &failingClientStorage{Storage: storage.NewStorage(storage.NewUserStore(testIssuer)), err: tt.storageErr}
				provider, err := op.NewOpenIDProvider(testIssuer, testConfig, s, op.WithAllowInsecure())
				require.NoError(t, err)

				// A valid code, so that the code flow reaches client authentication.
				ctx := op.ContextWithIssuer(context.Background(), testIssuer)
				authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
					ClientID:     "web",
					RedirectURI:  "https://example.com",
					Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
					ResponseType: oidc.ResponseTypeCode,
				}, "id1")
				require.NoError(t, err)
				require.NoError(t, s.SaveAuthCode(ctx, authReq.GetID(), "code"))
				require.NoError(t, s.AuthRequestDone(authReq.GetID()))

				req := httptest.NewRequest(http.MethodPost, provider.TokenEndpoint().Relative(), strings.NewReader(g.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(g.clientID, g.secret)
				rec := httptest.NewRecorder()
				provider.ServeHTTP(rec, req)

				var body struct {
					Error string `json:"error"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
				assert.Equal(t, tt.wantStatus, rec.Code, rec.Body.String())
				assert.Equal(t, tt.wantType, body.Error)
			})
		}
	}
}

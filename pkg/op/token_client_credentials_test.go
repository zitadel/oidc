package op_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
	"github.com/zitadel/schema"
)

// TestParseClientCredentialsRequest pins RFC 6749 §2.3 for the bare
// client_credentials exchange: the client MUST NOT use more than one
// authentication method in each request. The generic and legacy Server
// stacks perform the same check (webServer.parseClientCredentials and
// ParseAuthenticatedTokenRequest respectively); ParseClientCredentialsRequest
// is the remaining entry point used by ClientCredentialsExchange.
func TestParseClientCredentialsRequest(t *testing.T) {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	tests := []struct {
		name    string
		r       *http.Request
		wantErr error
	}{
		{
			name: "client_id+client_secret in body",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("grant_type=client_credentials&client_id=myid&client_secret=mysecret")),
		},
		{
			name: "client_assertion only in body",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("grant_type=client_credentials&client_assertion=xxx&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer")),
		},
		{
			name: "basic auth only",
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("grant_type=client_credentials"))
				r.SetBasicAuth("myid", "mysecret")
				return r
			}(),
		},
		{
			// RFC 6749 §2.3: a JWT assertion combined with client_secret
			// credentials is multiple authentication methods and must be
			// refused instead of silently ignoring the extra credentials.
			name: "client_assertion and client_id+client_secret in body",
			r: httptest.NewRequest(http.MethodPost, "/",
				strings.NewReader("grant_type=client_credentials&client_id=myid&client_secret=mysecret&client_assertion=xxx&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method"),
		},
		{
			name: "basic auth and client_assertion in body",
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/",
					strings.NewReader("grant_type=client_credentials&client_assertion=xxx&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
				r.SetBasicAuth("myid", "mysecret")
				return r
			}(),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method"),
		},
		{
			name: "basic auth and client_id+client_secret in body",
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/",
					strings.NewReader("grant_type=client_credentials&client_id=myid&client_secret=mysecret"))
				r.SetBasicAuth("myid", "mysecret")
				return r
			}(),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request, err := op.ParseClientCredentialsRequest(tt.r, decoder)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr == nil {
				require.NoError(t, err)
				require.NotNil(t, request)
			}
		})
	}
}

// TestLegacyServer_VerifyClient_UnsupportedGrant pins the ordering Copilot
// flagged: a provider that supports JWT verification (AuthMethodPrivateKeyJWT)
// but whose storage does not implement ClientCredentialsStorage must reject
// a client_credentials request with unsupported_grant_type BEFORE any
// assertion key lookup or signature verification. The gomock storage has no
// expected calls, so any storage access fails the test.
func TestLegacyServer_VerifyClient_UnsupportedGrant(t *testing.T) {
	ctrl := gomock.NewController(t)
	storageMock := mock.NewMockStorage(ctrl)

	// A provider that advertises private_key_jwt support, with a storage
	// that does not implement ClientCredentialsStorage.
	config := &op.Config{
		AuthMethodPrivateKeyJWT: true,
	}
	provider, err := op.NewOpenIDProvider(testIssuer, config, storageMock, op.WithAllowInsecure())
	require.NoError(t, err)

	server := op.NewLegacyServer(provider, *op.DefaultEndpoints)

	form := url.Values{
		"grant_type":            {string(oidc.GrantTypeClientCredentials)},
		"client_assertion":      {"not-a-real-jwt"},
		"client_assertion_type": {string(oidc.ClientAssertionTypeJWTAssertion)},
	}
	req := &op.Request[op.ClientCredentials]{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/oauth/token"},
		Form:   form,
		Data: &op.ClientCredentials{
			ClientAssertion:     "not-a-real-jwt",
			ClientAssertionType: oidc.ClientAssertionTypeJWTAssertion,
		},
	}

	client, err := server.VerifyClient(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, client)

	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, oidc.ErrUnsupportedGrantType().ErrorType, oidcErr.ErrorType)
	assert.Equal(t, "client_credentials grant not supported", oidcErr.Description)
}

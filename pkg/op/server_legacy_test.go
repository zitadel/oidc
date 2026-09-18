package op_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestLegacyServer_CodeExchange_ClientOwnership(t *testing.T) {
	server := op.RegisterLegacyServer(
		op.NewLegacyServer(testProvider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(testProvider),
	)

	storage := testProvider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)

	// Client A ("web") — the legitimate owner of the authorization code.
	clientA, err := storage.GetClientByClientID(ctx, "web")
	require.NoError(t, err)

	authReq, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     clientA.GetID(),
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: oidc.ResponseTypeCode,
	}, "user-1")
	require.NoError(t, err)
	storage.AuthRequestDone(authReq.GetID())
	storage.SaveAuthCode(ctx, authReq.GetID(), "test-code-x")

	// Client B ("api") — attempts to exchange a code it does not own.
	clientB, err := storage.GetClientByClientID(ctx, "api")
	require.NoError(t, err)

	form := url.Values{
		"grant_type":   {string(oidc.GrantTypeCode)},
		"code":         {"test-code-x"},
		"redirect_uri": {"https://example.com"},
	}

	u, err := url.Parse(testProvider.TokenEndpoint().Absolute(testIssuer))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientB.GetID(), "secret")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	resp := rec.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var errResp oidc.Error
	err = json.Unmarshal(body, &errResp)
	require.NoError(t, err)

	require.Equal(t, oidc.ErrInvalidGrant().Error(), errResp.Error())
	require.Empty(t, errResp.Description,
		"client mismatch must not include a description — it would leak information")
}

// A request object a provider does not support is refused in Authorize, after
// the redirect_uri has been validated, so the refusal is delivered to the
// client rather than rendered at the authorization endpoint.
func TestLegacyServer_Authorize_RequestObjectNotSupported(t *testing.T) {
	config := *testConfig
	config.RequestObjectSupported = false
	provider := newTestProvider(&config)

	server := op.RegisterLegacyServer(
		op.NewLegacyServer(provider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(provider),
	)

	tests := []struct {
		name        string
		idTokenHint string
		wantError   string
	}{
		{
			name:      "request object refused",
			wantError: "request_not_supported",
		},
		{
			// The refusal is raised after ValidateAuthReqIDTokenHint, the
			// position the Provider path uses, so an invalid id_token_hint is
			// reported in preference to the unsupported request object.
			name:        "id_token_hint checked first",
			idTokenHint: "not.a.token",
			wantError:   "login_required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := url.Values{
				"client_id":     {"web"},
				"redirect_uri":  {"https://example.com"},
				"response_type": {string(oidc.ResponseTypeCode)},
				"scope":         {oidc.ScopeOpenID},
				"state":         {"state-1"},
				"request":       {"not.a.request.object"},
			}
			if tt.idTokenHint != "" {
				query.Set("id_token_hint", tt.idTokenHint)
			}

			u, err := url.Parse(provider.AuthorizationEndpoint().Absolute(testIssuer))
			require.NoError(t, err)
			u.RawQuery = query.Encode()

			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.String(), nil))

			require.Equal(t, http.StatusFound, rec.Code)
			location, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "https://example.com", location.Scheme+"://"+location.Host)
			assert.Equal(t, tt.wantError, location.Query().Get("error"))
			assert.Equal(t, "state-1", location.Query().Get("state"))
		})
	}
}

// The callback reads the request id back with Form.Get, which decodes it, so an
// id containing reserved characters must survive the round trip unchanged.
func TestAuthCallbackURL_EscapesRequestID(t *testing.T) {
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	const requestID = "a+b/c=d&e#f %"

	builders := map[string]func(context.Context, string) string{
		"provider":      op.AuthCallbackURL(testProvider),
		"legacy server": op.NewLegacyServer(testProvider, *op.DefaultEndpoints).AuthCallbackURL(),
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			callback, err := url.Parse(build(ctx, requestID))
			require.NoError(t, err)
			require.Equal(t, requestID, callback.Query().Get("id"))
			require.Empty(t, callback.Fragment)
		})
	}
}

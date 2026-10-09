package op_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// newIssTestProvider returns a provider over its own storage, with RFC 9207 iss enabled or not.
func newIssTestProvider(enabled bool) op.OpenIDProvider {
	config := *testConfig
	config.AuthorizationResponseIssParameterSupported = enabled
	return newTestProvider(&config)
}

// doneAuthRequest stores a finished code flow auth request for the web client and returns its ID.
func doneAuthRequest(t *testing.T, provider op.OpenIDProvider, responseMode oidc.ResponseMode) string {
	t.Helper()
	storage := provider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	authReq, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "web",
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: oidc.ResponseTypeCode,
		ResponseMode: responseMode,
		State:        "state1",
	}, "id1")
	require.NoError(t, err)
	require.NoError(t, storage.AuthRequestDone(authReq.GetID()))
	return authReq.GetID()
}

// redirectParams returns the query of the Location header of rec.
func redirectParams(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	return location.Query()
}

func TestAuthorizationResponseIss(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		provider := newIssTestProvider(enabled)
		wantIss := ""
		if enabled {
			wantIss = testIssuer
		}

		t.Run(fmt.Sprintf("enabled=%t/discovery", enabled), func(t *testing.T) {
			rec := httptest.NewRecorder()
			provider.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, testIssuer+oidc.DiscoveryEndpoint[1:], nil))
			require.Equal(t, http.StatusOK, rec.Code)
			var config oidc.DiscoveryConfiguration
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &config))
			assert.Equal(t, enabled, config.AuthorizationResponseIssParameterSupported)
		})

		for _, path := range authorizePaths(provider) {
			t.Run(fmt.Sprintf("enabled=%t/%s/error from storage", enabled, path.name), func(t *testing.T) {
				rec := getAuthorize(t, provider, path.handler, url.Values{
					"client_id":     {"web"},
					"redirect_uri":  {"https://example.com"},
					"response_type": {string(oidc.ResponseTypeCode)},
					"scope":         {oidc.ScopeOpenID},
					"state":         {"state1"},
					"prompt":        {oidc.PromptNone},
				})
				params := redirectParams(t, rec)
				assert.Equal(t, string(oidc.LoginRequired), params.Get("error"))
				assert.Equal(t, "state1", params.Get("state"))
				assert.Equal(t, wantIss, params.Get("iss"))
			})

			t.Run(fmt.Sprintf("enabled=%t/%s/error from validation", enabled, path.name), func(t *testing.T) {
				rec := getAuthorize(t, provider, path.handler, url.Values{
					"client_id":     {"web"},
					"redirect_uri":  {"https://example.com"},
					"response_type": {string(oidc.ResponseTypeCode)},
					"scope":         {oidc.ScopeOpenID},
					"state":         {"state1"},
					"prompt":        {oidc.PromptNone + " " + oidc.PromptLogin},
				})
				params := redirectParams(t, rec)
				assert.Equal(t, string(oidc.InvalidRequest), params.Get("error"))
				assert.Equal(t, wantIss, params.Get("iss"))
			})

			t.Run(fmt.Sprintf("enabled=%t/%s/code", enabled, path.name), func(t *testing.T) {
				id := doneAuthRequest(t, provider, "")
				rec := httptest.NewRecorder()
				path.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, op.AuthCallbackURL(provider)(op.ContextWithIssuer(context.Background(), testIssuer), id), nil))
				params := redirectParams(t, rec)
				assert.NotEmpty(t, params.Get("code"))
				assert.Equal(t, "state1", params.Get("state"))
				assert.Equal(t, wantIss, params.Get("iss"))
			})

			t.Run(fmt.Sprintf("enabled=%t/%s/code form_post", enabled, path.name), func(t *testing.T) {
				id := doneAuthRequest(t, provider, oidc.ResponseModeFormPost)
				rec := httptest.NewRecorder()
				path.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, op.AuthCallbackURL(provider)(op.ContextWithIssuer(context.Background(), testIssuer), id), nil))
				require.Equal(t, http.StatusOK, rec.Code)
				issInput := fmt.Sprintf(`<input type="hidden" name="iss" value="%s" />`, testIssuer)
				if enabled {
					assert.Contains(t, rec.Body.String(), issInput)
				} else {
					assert.NotContains(t, rec.Body.String(), `name="iss"`)
				}
			})
		}
	}
}

func TestAuthResponseURLWithIssuer(t *testing.T) {
	response := map[string][]string{"code": {"abc"}, "state": {"state1"}}
	tests := []struct {
		name         string
		responseType oidc.ResponseType
		responseMode oidc.ResponseMode
		issuer       string
		want         string
	}{
		{
			name:         "query",
			responseType: oidc.ResponseTypeCode,
			issuer:       testIssuer,
			want:         "https://example.com/cb?code=abc&iss=https%3A%2F%2Flocalhost%3A9998%2F&state=state1",
		},
		{
			name:         "fragment",
			responseType: oidc.ResponseTypeIDToken,
			issuer:       testIssuer,
			want:         "https://example.com/cb#code=abc&iss=https%3A%2F%2Flocalhost%3A9998%2F&state=state1",
		},
		{
			name:         "no issuer",
			responseType: oidc.ResponseTypeCode,
			want:         "https://example.com/cb?code=abc&state=state1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.AuthResponseURLWithIssuer("https://example.com/cb", tt.responseType, tt.responseMode, response, &mockEncoder{}, tt.issuer)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

type issuerSupport bool

func (s issuerSupport) AuthorizationResponseIssParameterSupported() bool { return bool(s) }

func TestAuthorizationResponseIssFromContext(t *testing.T) {
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	assert.Equal(t, "", op.AuthorizationResponseIss(ctx, struct{}{}), "not implemented")
	assert.Equal(t, "", op.AuthorizationResponseIss(ctx, issuerSupport(false)), "disabled")
	assert.Equal(t, testIssuer, op.AuthorizationResponseIss(ctx, issuerSupport(true)), "enabled")
}

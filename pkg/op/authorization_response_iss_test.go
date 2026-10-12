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

// doneAuthRequest stores a finished auth request for the web client and returns its ID.
func doneAuthRequest(t *testing.T, provider op.OpenIDProvider, responseType oidc.ResponseType, responseMode oidc.ResponseMode) string {
	t.Helper()
	storage := provider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	authReq, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "web",
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: responseType,
		ResponseMode: responseMode,
		State:        "state1",
		Nonce:        "nonce1",
	}, "id1")
	require.NoError(t, err)
	require.NoError(t, storage.AuthRequestDone(authReq.GetID()))
	return authReq.GetID()
}

// callback sends the auth callback for a finished auth request to handler.
func callback(provider op.OpenIDProvider, handler http.Handler, id string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	callbackURL := op.AuthCallbackURL(provider)(op.ContextWithIssuer(context.Background(), testIssuer), id)
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, callbackURL, nil))
	return rec
}

// redirectLocation returns the Location header of rec, which must be a redirect.
func redirectLocation(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	return location
}

// assertFormPostIss checks that a form_post response carries iss if, and only if, wantIss is set.
func assertFormPostIss(t *testing.T, rec *httptest.ResponseRecorder, wantIss string) {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code)
	if wantIss == "" {
		assert.NotContains(t, rec.Body.String(), `name="iss"`)
		return
	}
	assert.Contains(t, rec.Body.String(), fmt.Sprintf(`<input type="hidden" name="iss" value="%s" />`, wantIss))
}

func TestAuthorizationResponseIss(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		provider := newIssTestProvider(enabled)
		wantIss := ""
		if enabled {
			wantIss = testIssuer
		}

		for _, path := range authorizePaths(provider) {
			name := fmt.Sprintf("enabled=%t/%s/", enabled, path.name)

			t.Run(name+"discovery", func(t *testing.T) {
				rec := httptest.NewRecorder()
				path.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, testIssuer+oidc.DiscoveryEndpoint[1:], nil))
				require.Equal(t, http.StatusOK, rec.Code)
				var config oidc.DiscoveryConfiguration
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &config))
				assert.Equal(t, enabled, config.AuthorizationResponseIssParameterSupported)
			})

			t.Run(name+"error from storage", func(t *testing.T) {
				rec := getAuthorize(t, provider, path.handler, url.Values{
					"client_id":     {"web"},
					"redirect_uri":  {"https://example.com"},
					"response_type": {string(oidc.ResponseTypeCode)},
					"scope":         {oidc.ScopeOpenID},
					"state":         {"state1"},
					"prompt":        {oidc.PromptNone},
				})
				params := redirectLocation(t, rec).Query()
				assert.Equal(t, string(oidc.LoginRequired), params.Get("error"))
				assert.Equal(t, "state1", params.Get("state"))
				assert.Equal(t, wantIss, params.Get("iss"))
			})

			t.Run(name+"error from validation", func(t *testing.T) {
				rec := getAuthorize(t, provider, path.handler, url.Values{
					"client_id":     {"web"},
					"redirect_uri":  {"https://example.com"},
					"response_type": {string(oidc.ResponseTypeCode)},
					"scope":         {oidc.ScopeOpenID},
					"state":         {"state1"},
					"prompt":        {oidc.PromptNone + " " + oidc.PromptLogin},
				})
				params := redirectLocation(t, rec).Query()
				assert.Equal(t, string(oidc.InvalidRequest), params.Get("error"))
				assert.Equal(t, wantIss, params.Get("iss"))
			})

			t.Run(name+"code", func(t *testing.T) {
				rec := callback(provider, path.handler, doneAuthRequest(t, provider, oidc.ResponseTypeCode, ""))
				params := redirectLocation(t, rec).Query()
				assert.NotEmpty(t, params.Get("code"))
				assert.Equal(t, "state1", params.Get("state"))
				assert.Equal(t, wantIss, params.Get("iss"))
			})

			t.Run(name+"code form_post", func(t *testing.T) {
				rec := callback(provider, path.handler, doneAuthRequest(t, provider, oidc.ResponseTypeCode, oidc.ResponseModeFormPost))
				assertFormPostIss(t, rec, wantIss)
			})

			t.Run(name+"token", func(t *testing.T) {
				rec := callback(provider, path.handler, doneAuthRequest(t, provider, oidc.ResponseTypeIDToken, ""))
				location := redirectLocation(t, rec)
				params, err := url.ParseQuery(location.Fragment)
				require.NoError(t, err)
				assert.NotEmpty(t, params.Get("access_token"))
				assert.NotEmpty(t, params.Get("id_token"))
				assert.Equal(t, wantIss, params.Get("iss"))
			})

			t.Run(name+"token form_post", func(t *testing.T) {
				rec := callback(provider, path.handler, doneAuthRequest(t, provider, oidc.ResponseTypeIDToken, oidc.ResponseModeFormPost))
				assert.Contains(t, rec.Body.String(), `name="id_token"`)
				assertFormPostIss(t, rec, wantIss)
			})
		}
	}
}

func TestAuthResponseURLWithIssuer(t *testing.T) {
	response := map[string][]string{"code": {"abc"}, "state": {"state1"}}
	tests := []struct {
		name         string
		redirectURI  string
		responseType oidc.ResponseType
		issuer       string
		want         string
	}{
		{
			name:         "query",
			redirectURI:  "https://example.com/cb",
			responseType: oidc.ResponseTypeCode,
			issuer:       testIssuer,
			want:         "https://example.com/cb?code=abc&iss=https%3A%2F%2Flocalhost%3A9998%2F&state=state1",
		},
		{
			name:         "fragment",
			redirectURI:  "https://example.com/cb",
			responseType: oidc.ResponseTypeIDToken,
			issuer:       testIssuer,
			want:         "https://example.com/cb#code=abc&iss=https%3A%2F%2Flocalhost%3A9998%2F&state=state1",
		},
		{
			name:         "no issuer",
			redirectURI:  "https://example.com/cb",
			responseType: oidc.ResponseTypeCode,
			want:         "https://example.com/cb?code=abc&state=state1",
		},
		{
			name:         "query, redirect URI with iss",
			redirectURI:  "https://example.com/cb?iss=https%3A%2F%2Fother.example%2F&x=1",
			responseType: oidc.ResponseTypeCode,
			issuer:       testIssuer,
			want:         "https://example.com/cb?code=abc&iss=https%3A%2F%2Flocalhost%3A9998%2F&state=state1&x=1",
		},
		{
			name:         "fragment, redirect URI with iss",
			redirectURI:  "https://example.com/cb?iss=https%3A%2F%2Fother.example%2F&x=1",
			responseType: oidc.ResponseTypeIDToken,
			issuer:       testIssuer,
			want:         "https://example.com/cb?x=1#code=abc&iss=https%3A%2F%2Flocalhost%3A9998%2F&state=state1",
		},
		{
			name:         "no issuer, redirect URI with iss",
			redirectURI:  "https://example.com/cb?iss=https%3A%2F%2Fother.example%2F",
			responseType: oidc.ResponseTypeCode,
			want:         "https://example.com/cb?code=abc&iss=https%3A%2F%2Fother.example%2F&state=state1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.AuthResponseURLWithIssuer(tt.redirectURI, tt.responseType, "", response, &mockEncoder{}, tt.issuer)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthResponseFormPostWithIssuer(t *testing.T) {
	response := map[string][]string{"code": {"abc"}, "state": {"state1"}}
	redirectURI := "https://example.com/cb?iss=https%3A%2F%2Fother.example%2F&x=1"

	t.Run("issuer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		require.NoError(t, op.AuthResponseFormPostWithIssuer(rec, redirectURI, response, &mockEncoder{}, testIssuer))
		assert.Contains(t, rec.Body.String(), `action="https://example.com/cb?x=1"`)
		assertFormPostIss(t, rec, testIssuer)
	})

	t.Run("no issuer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		require.NoError(t, op.AuthResponseFormPostWithIssuer(rec, redirectURI, response, &mockEncoder{}, ""))
		assert.Contains(t, rec.Body.String(), `action="https://example.com/cb?iss=https%3A%2F%2Fother.example%2F&amp;x=1"`)
		assertFormPostIss(t, rec, "")
	})
}

type issuerSupport bool

func (s issuerSupport) AuthorizationResponseIssParameterSupported() bool { return bool(s) }

func TestAuthorizationResponseIssFromContext(t *testing.T) {
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	assert.Equal(t, "", op.AuthorizationResponseIss(ctx, struct{}{}), "not implemented")
	assert.Equal(t, "", op.AuthorizationResponseIss(ctx, issuerSupport(false)), "disabled")
	assert.Equal(t, testIssuer, op.AuthorizationResponseIss(ctx, issuerSupport(true)), "enabled")
}

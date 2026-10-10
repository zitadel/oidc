package op_test

import (
	"encoding/json"
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
	implicitClientID    = "implicit-client"
	implicitRedirectURI = "http://localhost:9997/callback"
	grantClientID       = "grant-client"
)

// codeOnlyConfig is a provider configuration that turns the implicit flow and
// the id_token response types off, which previous versions had no way to
// express: discovery always advertised them.
func codeOnlyConfig() *op.Config {
	config := *testConfig
	config.SupportedResponseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
	config.SupportedGrantTypes = []oidc.GrantType{oidc.GrantTypeCode}
	return &config
}

// getDiscovery fetches and decodes the provider discovery document.
func getDiscovery(t *testing.T, provider op.OpenIDProvider) *oidc.DiscoveryConfiguration {
	t.Helper()
	u, err := url.Parse(testIssuer)
	require.NoError(t, err)
	u.Path = oidc.DiscoveryEndpoint
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.String(), nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	config := new(oidc.DiscoveryConfiguration)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), config))
	return config
}

// TestDiscoveryResponseAndGrantTypesDefaults pins that a provider without the
// new configuration fields advertises exactly what previous versions did, so
// the defaults are backwards compatible.
func TestDiscoveryResponseAndGrantTypesDefaults(t *testing.T) {
	provider := newTestProvider(&op.Config{})
	discovery := getDiscovery(t, provider)

	assert.Equal(t, []string{
		string(oidc.ResponseTypeCode),
		string(oidc.ResponseTypeIDTokenOnly),
		string(oidc.ResponseTypeIDToken),
	}, discovery.ResponseTypesSupported)

	assert.Contains(t, discovery.GrantTypesSupported, oidc.GrantTypeCode)
	assert.Contains(t, discovery.GrantTypesSupported, oidc.GrantTypeImplicit)
}

// TestDiscoveryCodeOnly pins the code-only scenario: an operator that restricts
// response types to code gets a discovery document that no longer advertises
// the implicit flow, and one that still advertises every grant the server
// actually serves.
func TestDiscoveryCodeOnly(t *testing.T) {
	provider := newTestProvider(codeOnlyConfig())
	discovery := getDiscovery(t, provider)

	assert.Equal(t, []string{string(oidc.ResponseTypeCode)}, discovery.ResponseTypesSupported)
	assert.NotContains(t, discovery.GrantTypesSupported, oidc.GrantTypeImplicit)
	// The authorization code grant cannot be turned off: it is required by
	// OIDC Core section 2 and the provider callback is built around it.
	assert.Contains(t, discovery.GrantTypesSupported, oidc.GrantTypeCode)
}

// assertDeliveredError asserts that rec is an RFC 6749 4.1.2.1 error response
// delivered to wantRedirectURI and returns its parameters.
func assertDeliveredError(t *testing.T, rec *httptest.ResponseRecorder, wantError, wantRedirectURI, wantState string) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code)

	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, wantRedirectURI, location.Scheme+"://"+location.Host+location.Path)

	params := location.Query()
	if fragment := location.EscapedFragment(); fragment != "" {
		// A response type that is not code defaults to response_mode
		// fragment, which both paths honour.
		params, err = url.ParseQuery(fragment)
		require.NoError(t, err)
	}
	assert.Equal(t, wantError, params.Get("error"))
	assert.Equal(t, wantState, params.Get("state"),
		"state must be echoed, or the client cannot correlate the error")
	return params
}

// TestAuthorizeRejectsDisabledResponseType drives both /authorize paths with a
// response type the client allows but the provider does not. Previous versions
// had no way to refuse such a request: the only check ran against the client.
func TestAuthorizeRejectsDisabledResponseType(t *testing.T) {
	// A web client allows every response type at the client level, so the
	// provider list is the only refusal point.
	storage.RegisterClients(storage.WebClient(implicitClientID, "secret", implicitRedirectURI))

	provider := newTestProvider(codeOnlyConfig())
	query := url.Values{
		"client_id":     {implicitClientID},
		"redirect_uri":  {implicitRedirectURI},
		"response_type": {string(oidc.ResponseTypeIDTokenOnly)},
		"scope":         {oidc.ScopeOpenID},
		"state":         {"code-only-state"},
	}

	for _, path := range authorizePaths(provider) {
		t.Run(path.name, func(t *testing.T) {
			rec := getAuthorize(t, provider, path.handler, query)

			params := assertDeliveredError(t, rec, "unsupported_response_type", implicitRedirectURI, "code-only-state")
			assert.NotEmpty(t, params.Get("error_description"))
		})
	}
}

// TestAuthorizeRejectsResponseTypeCodeToo pins that even the response type code
// is refused when the operator list omits it, so the list is authoritative for
// the response types the authorization endpoint accepts. Discovery keeps
// advertising it, because OIDC Core requires it; the PR body documents this.
func TestAuthorizeRejectsResponseTypeCodeToo(t *testing.T) {
	storage.RegisterClients(storage.WebClient(implicitClientID, "secret", implicitRedirectURI))

	config := *testConfig
	config.SupportedResponseTypes = []oidc.ResponseType{oidc.ResponseTypeIDTokenOnly}
	provider := newTestProvider(&config)
	query := url.Values{
		"client_id":     {implicitClientID},
		"redirect_uri":  {implicitRedirectURI},
		"response_type": {string(oidc.ResponseTypeCode)},
		"scope":         {oidc.ScopeOpenID},
		"state":         {"no-code-state"},
	}

	for _, path := range authorizePaths(provider) {
		t.Run(path.name, func(t *testing.T) {
			rec := getAuthorize(t, provider, path.handler, query)
			assertDeliveredError(t, rec, "unsupported_response_type", implicitRedirectURI, "no-code-state")
		})
	}
}

// TestAuthorizeAcceptsConfiguredResponseType pins that a response type listed
// in the provider configuration is still accepted end-to-end, so the new gate
// does not over-block.
func TestAuthorizeAcceptsConfiguredResponseType(t *testing.T) {
	storage.RegisterClients(storage.WebClient(implicitClientID, "secret", implicitRedirectURI))

	provider := newTestProvider(codeOnlyConfig())
	query := url.Values{
		"client_id":     {implicitClientID},
		"redirect_uri":  {implicitRedirectURI},
		"response_type": {string(oidc.ResponseTypeCode)},
		"scope":         {oidc.ScopeOpenID},
		"state":         {"code-ok-state"},
	}

	for _, path := range authorizePaths(provider) {
		t.Run(path.name, func(t *testing.T) {
			rec := getAuthorize(t, provider, path.handler, query)

			// The request passes validation and is handed to the login.
			require.Equal(t, http.StatusFound, rec.Code)
			location, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			assert.Contains(t, location.String(), "/login/username?authRequestID=")
		})
	}
}

// TestGrantTypesOverrideRejectsAtTokenEndpoint pins that a grant type the
// operator removed from the configuration is refused at the token endpoint and
// absent from the discovery document.
func TestGrantTypesOverrideRejectsAtTokenEndpoint(t *testing.T) {
	storage.RegisterClients(storage.WebClient(grantClientID, "secret"))

	// Refresh tokens are enabled by testConfig, so removing the grant from
	// the explicit list is the only way to turn it off.
	config := *testConfig
	config.SupportedGrantTypes = []oidc.GrantType{oidc.GrantTypeCode}
	provider := newTestProvider(&config)

	discovery := getDiscovery(t, provider)
	assert.NotContains(t, discovery.GrantTypesSupported, oidc.GrantTypeRefreshToken)
	assert.False(t, provider.GrantTypeRefreshTokenSupported())

	form := url.Values{
		"grant_type":    {string(oidc.GrantTypeRefreshToken)},
		"refresh_token": {"invalid-but-present"},
	}
	u, err := url.Parse(provider.TokenEndpoint().Absolute(testIssuer))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(grantClientID, "secret")

	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "unsupported_grant_type")
}

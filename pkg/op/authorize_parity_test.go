package op_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	// A native client, so the only registered response type is `code` and the
	// loopback redirect_uri below is accepted without dev mode.
	parityClientID    = "parity"
	parityRedirectURI = "http://localhost:9999/callback"
	parityState       = "parity-state"
)

// authorizePath is one of the two /authorize implementations the library
// ships, both over the same provider.
type authorizePath struct {
	name    string
	handler http.Handler
}

func authorizePaths(provider op.OpenIDProvider) []authorizePath {
	return []authorizePath{
		{name: "Provider", handler: provider},
		{name: "op.Server", handler: op.RegisterLegacyServer(
			op.NewLegacyServer(provider, *op.DefaultEndpoints),
			op.AuthorizeCallbackHandler(provider),
		)},
	}
}

// getAuthorize sends query to the provider's authorization endpoint.
func getAuthorize(t *testing.T, provider op.OpenIDProvider, handler http.Handler, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(provider.AuthorizationEndpoint().Absolute(testIssuer))
	require.NoError(t, err)
	u.RawQuery = query.Encode()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.String(), nil))
	return rec
}

// parityQuery is an /authorize request the client is entitled to make, for a
// case to break in exactly one way.
func parityQuery() url.Values {
	return url.Values{
		"client_id":     {parityClientID},
		"redirect_uri":  {parityRedirectURI},
		"response_type": {string(oidc.ResponseTypeCode)},
		"scope":         {oidc.ScopeOpenID},
		"state":         {parityState},
	}
}

// assertDelivered asserts that rec is an RFC 6749 4.1.2.1 error response
// delivered to the client's redirect_uri, and returns its parameters so the
// caller can assert what applies to its own case.
func assertDelivered(t *testing.T, rec *httptest.ResponseRecorder, wantError string) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code)

	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, parityRedirectURI, location.Scheme+"://"+location.Host+location.Path)

	params := location.Query()
	if fragment := location.EscapedFragment(); fragment != "" {
		// A response type that is not `code` defaults to response_mode
		// fragment, which both paths honour.
		params, err = url.ParseQuery(fragment)
		require.NoError(t, err)
	}
	assert.Equal(t, wantError, params.Get("error"))
	assert.Equal(t, parityState, params.Get("state"),
		"state must be echoed, or the client cannot correlate the error")
	return params
}

// TestAuthorizeErrorParity holds the two dispatch paths to the same answer for
// the same malformed /authorize request. The rendered refusals differ in body
// by design, since the Provider path writes text/plain through http.Error
// while the op.Server path writes JSON, so only the status, the Location and
// the delivered parameters are compared.
func TestAuthorizeErrorParity(t *testing.T) {
	storage.RegisterClients(storage.NativeClient(parityClientID, parityRedirectURI))

	tests := []struct {
		name string
		// break mutates an otherwise valid request into the one under test.
		break_ func(url.Values)
		// wantError is the error code expected at the client's redirect_uri.
		// Empty means the refusal must be rendered at the endpoint instead.
		wantError string
	}{
		{
			// The reported symptom: a response type the client has not
			// registered is the client's error to see, not the endpoint's to
			// render.
			name:      "unregistered response_type",
			break_:    func(q url.Values) { q.Set("response_type", string(oidc.ResponseTypeIDToken)) },
			wantError: "unauthorized_client",
		},
		{
			name:      "prompt none with another value",
			break_:    func(q url.Values) { q.Set("prompt", "none consent") },
			wantError: "invalid_request",
		},
		{
			name:      "missing scope",
			break_:    func(q url.Values) { q.Del("scope") },
			wantError: "invalid_request",
		},
		{
			// Nothing has been validated against the client yet, so there is
			// no redirect_uri to deliver to.
			name:   "missing redirect_uri",
			break_: func(q url.Values) { q.Del("redirect_uri") },
		},
		{
			// Delivering here would make the endpoint an open redirect.
			name:   "unregistered redirect_uri",
			break_: func(q url.Values) { q.Set("redirect_uri", "http://localhost:9999/elsewhere") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, path := range authorizePaths(testProvider) {
				t.Run(path.name, func(t *testing.T) {
					query := parityQuery()
					tt.break_(query)
					rec := getAuthorize(t, testProvider, path.handler, query)

					if tt.wantError == "" {
						assert.Equal(t, http.StatusBadRequest, rec.Code)
						assert.Empty(t, rec.Header().Get("Location"),
							"a refusal raised before the redirect_uri was validated must not be delivered")
						return
					}
					params := assertDelivered(t, rec, tt.wantError)
					assert.NotEmpty(t, params.Get("error_description"))
				})
			}
		})
	}
}

// TestAuthorizeRequestObjectNotSupportedParity covers the one refusal that
// needs a provider configured without Request Object support, which the shared
// testProvider has enabled.
func TestAuthorizeRequestObjectNotSupportedParity(t *testing.T) {
	storage.RegisterClients(storage.NativeClient(parityClientID, parityRedirectURI))

	config := *testConfig
	config.RequestObjectSupported = false
	provider := newTestProvider(&config)

	for _, path := range authorizePaths(provider) {
		t.Run(path.name, func(t *testing.T) {
			query := parityQuery()
			query.Set("request", "not.a.request.object")

			assertDelivered(t, getAuthorize(t, provider, path.handler, query), "request_not_supported")
		})
	}
}

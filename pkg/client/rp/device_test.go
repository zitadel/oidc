package rp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

// deviceCall is what an endpoint of the test OP received.
type deviceCall struct {
	form                 url.Values
	header               http.Header
	basicUser, basicPass string
	hasBasic             bool
}

// authMethods counts the client authentication methods in the request.
func (c deviceCall) authMethods() int {
	n := 0
	for _, used := range []bool{c.hasBasic, c.form.Has("client_secret"), c.form.Has("client_assertion")} {
		if used {
			n++
		}
	}
	return n
}

// newDeviceOP serves the device authorization endpoint at / and the token
// endpoint at /token, recording the last request each one received.
func newDeviceOP(t *testing.T, authz, token *deviceCall) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got := authz
		body := map[string]any{
			"device_code":      "device-code",
			"user_code":        "user-code",
			"verification_uri": "https://example.com/device",
			"expires_in":       600,
			"interval":         5,
		}
		if r.URL.Path == "/token" {
			got = token
			body = map[string]any{"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600}
		}
		if got != nil {
			got.form = r.PostForm
			got.header = r.Header
			got.basicUser, got.basicPass, got.hasBasic = r.BasicAuth()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newDeviceRP(srv *httptest.Server, issuer string, style oauth2.AuthStyle, signer jose.Signer) *relyingParty {
	return &relyingParty{
		issuer: issuer,
		oauthConfig: &oauth2.Config{
			ClientID:     "client",
			ClientSecret: "secret",
			Endpoint:     oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthStyle: style},
		},
		endpoints:  Endpoints{DeviceAuthorizationURL: srv.URL},
		httpClient: srv.Client(),
		signer:     signer,
	}
}

func newTestSigner(t *testing.T) jose.Signer {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: mustRSAKey(t, 2048)}, nil)
	require.NoError(t, err)
	return signer
}

// failingSigner stands in for a signer that is unavailable, such as a KMS outage.
type failingSigner struct{}

func (failingSigner) Sign([]byte) (*jose.JSONWebSignature, error) {
	return nil, errors.New("signer unavailable")
}

func (failingSigner) Options() jose.SignerOptions { return jose.SignerOptions{} }

// assertionAudience decodes the aud claim of a client assertion.
func assertionAudience(t *testing.T, assertion string) []string {
	t.Helper()
	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Audience json.RawMessage `json:"aud"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	var aud []string
	if err := json.Unmarshal(claims.Audience, &aud); err != nil {
		var single string
		require.NoError(t, json.Unmarshal(claims.Audience, &single))
		aud = []string{single}
	}
	return aud
}

func TestDeviceAuthorizationUsesOneAuthMethod(t *testing.T) {
	signer := newTestSigner(t)
	tenantHeader := httphelper.RequestAuthorization(func(r *http.Request) {
		r.Header.Set("X-Tenant", "t1")
	})
	var nilRequestAuth httphelper.RequestAuthorization
	pkce := httphelper.FormAuthorization(func(form url.Values) {
		form.Set("code_challenge", "challenge")
	})

	tests := []struct {
		name          string
		style         oauth2.AuthStyle
		signer        jose.Signer
		authFn        any
		wantBasic     bool
		wantSecret    bool
		wantAssertion bool
		wantTenant    bool
		wantChallenge bool
	}{
		{name: "secret in the form by default", style: oauth2.AuthStyleAutoDetect, wantSecret: true},
		{name: "secret in the form for AuthStyleInParams", style: oauth2.AuthStyleInParams, wantSecret: true},
		{name: "header only for AuthStyleInHeader", style: oauth2.AuthStyleInHeader, wantBasic: true},
		{name: "assertion replaces the secret", style: oauth2.AuthStyleAutoDetect, signer: signer, wantAssertion: true},
		{name: "header only for AuthStyleInHeader with a signer", style: oauth2.AuthStyleInHeader, signer: signer, wantBasic: true},
		{
			name:       "a header-only authFn keeps the form secret",
			style:      oauth2.AuthStyleAutoDetect,
			authFn:     tenantHeader,
			wantSecret: true,
			wantTenant: true,
		},
		{
			name:       "a header-only authFn is combined with basic auth",
			style:      oauth2.AuthStyleInHeader,
			authFn:     tenantHeader,
			wantBasic:  true,
			wantTenant: true,
		},
		{name: "a nil RequestAuthorization keeps the form secret", style: oauth2.AuthStyleAutoDetect, authFn: nilRequestAuth, wantSecret: true},
		{name: "a nil RequestAuthorization still gets basic auth", style: oauth2.AuthStyleInHeader, authFn: nilRequestAuth, wantBasic: true},
		{
			name:          "a FormAuthorization keeps the form secret",
			style:         oauth2.AuthStyleAutoDetect,
			authFn:        pkce,
			wantSecret:    true,
			wantChallenge: true,
		},
		{
			// A form change cannot be combined with a header, so the credentials
			// go in the form, as they did before AuthStyle was honoured.
			name:          "a FormAuthorization with AuthStyleInHeader keeps the form secret",
			style:         oauth2.AuthStyleInHeader,
			authFn:        pkce,
			wantSecret:    true,
			wantChallenge: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got deviceCall
			srv := newDeviceOP(t, &got, nil)

			_, err := DeviceAuthorization(context.Background(), []string{"openid"}, newDeviceRP(srv, srv.URL, tt.style, tt.signer), tt.authFn)
			require.NoError(t, err)

			// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
			assert.Equal(t, 1, got.authMethods(), "authentication methods in the request")
			assert.Equal(t, tt.wantBasic, got.hasBasic, "Authorization header")
			// Absent, not just empty: a strict OP may count a present parameter.
			assert.Equal(t, tt.wantSecret, got.form.Has("client_secret"), "client_secret in the form")
			assert.Equal(t, tt.wantAssertion, got.form.Has("client_assertion"), "client_assertion in the form")
			if tt.wantBasic {
				assert.Equal(t, "client", got.basicUser)
				assert.Equal(t, "secret", got.basicPass)
			}
			if tt.wantSecret {
				assert.Equal(t, "secret", got.form.Get("client_secret"))
			}
			assert.Equal(t, tt.wantTenant, got.header.Get("X-Tenant") == "t1", "caller header kept")
			assert.Equal(t, tt.wantChallenge, got.form.Get("code_challenge") == "challenge", "caller form field kept")
			assert.Equal(t, "client", got.form.Get("client_id"))
		})
	}
}

func TestDeviceAuthorizationSignsOnlyWhenTheAssertionIsSent(t *testing.T) {
	t.Run("basic auth does not need the signer", func(t *testing.T) {
		var got deviceCall
		srv := newDeviceOP(t, &got, nil)
		_, err := DeviceAuthorization(context.Background(), []string{"openid"}, newDeviceRP(srv, srv.URL, oauth2.AuthStyleInHeader, failingSigner{}), nil)
		require.NoError(t, err)
		assert.True(t, got.hasBasic)
	})
	t.Run("an assertion that cannot be signed fails the call", func(t *testing.T) {
		srv := newDeviceOP(t, nil, nil)
		_, err := DeviceAuthorization(context.Background(), []string{"openid"}, newDeviceRP(srv, srv.URL, oauth2.AuthStyleAutoDetect, failingSigner{}), nil)
		require.ErrorContains(t, err, "failed to build assertion")
	})
}

// An OAuth-only relying party has no issuer, so its assertions are addressed
// to the token endpoint, as in the other flows (RFC 7523, section 3).
func TestDeviceFlowAssertionAudience(t *testing.T) {
	signer := newTestSigner(t)
	for _, tt := range []struct {
		name   string
		issuer func(srv *httptest.Server) string
		want   func(srv *httptest.Server) string
	}{
		{
			name:   "issuer",
			issuer: func(srv *httptest.Server) string { return srv.URL },
			want:   func(srv *httptest.Server) string { return srv.URL },
		},
		{
			name:   "token endpoint without an issuer",
			issuer: func(*httptest.Server) string { return "" },
			want:   func(srv *httptest.Server) string { return srv.URL + "/token" },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var authz, token deviceCall
			srv := newDeviceOP(t, &authz, &token)
			rp := newDeviceRP(srv, tt.issuer(srv), oauth2.AuthStyleAutoDetect, signer)

			_, err := DeviceAuthorization(context.Background(), []string{"openid"}, rp, nil)
			require.NoError(t, err)
			assert.Equal(t, []string{tt.want(srv)}, assertionAudience(t, authz.form.Get("client_assertion")), "device authorization")

			_, err = DeviceAccessToken(context.Background(), "device-code", time.Millisecond, rp)
			require.NoError(t, err)
			assert.Equal(t, []string{tt.want(srv)}, assertionAudience(t, token.form.Get("client_assertion")), "device access token")
		})
	}
}

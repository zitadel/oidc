package rp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

// deviceAuthorizationCall is what the device authorization endpoint received.
type deviceAuthorizationCall struct {
	form                 url.Values
	basicUser, basicPass string
	hasBasic             bool
}

// authMethods counts the client authentication methods in the request. An
// empty client_secret is not a method, matching the OP's own check.
func (c deviceAuthorizationCall) authMethods() int {
	n := 0
	for _, used := range []bool{c.hasBasic, c.form.Get("client_secret") != "", c.form.Get("client_assertion") != ""} {
		if used {
			n++
		}
	}
	return n
}

func newDeviceAuthorizationServer(t *testing.T, got *deviceAuthorizationCall) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got.form = r.PostForm
		got.basicUser, got.basicPass, got.hasBasic = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "device-code",
			"user_code":        "user-code",
			"verification_uri": "https://example.com/device",
			"expires_in":       600,
			"interval":         5,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newDeviceRP(srv *httptest.Server, style oauth2.AuthStyle, signer jose.Signer) *relyingParty {
	return &relyingParty{
		issuer: srv.URL,
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

func TestDeviceAuthorizationUsesOneAuthMethod(t *testing.T) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: mustRSAKey(t, 2048)}, nil)
	require.NoError(t, err)

	tests := []struct {
		name          string
		style         oauth2.AuthStyle
		signer        jose.Signer
		authFn        any
		wantBasic     bool
		wantSecret    bool
		wantAssertion bool
	}{
		{name: "secret in the form by default", style: oauth2.AuthStyleAutoDetect, wantSecret: true},
		{name: "secret in the form for AuthStyleInParams", style: oauth2.AuthStyleInParams, wantSecret: true},
		{name: "header only for AuthStyleInHeader", style: oauth2.AuthStyleInHeader, wantBasic: true},
		{name: "assertion replaces the secret", style: oauth2.AuthStyleAutoDetect, signer: signer, wantAssertion: true},
		{name: "header only for AuthStyleInHeader with a signer", style: oauth2.AuthStyleInHeader, signer: signer, wantBasic: true},
		{
			name:      "caller authorization replaces the form secret",
			style:     oauth2.AuthStyleAutoDetect,
			authFn:    httphelper.AuthorizeBasic("client", "secret"),
			wantBasic: true,
		},
		{
			name:      "caller authorization replaces the assertion",
			style:     oauth2.AuthStyleAutoDetect,
			signer:    signer,
			authFn:    httphelper.AuthorizeBasic("client", "secret"),
			wantBasic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got deviceAuthorizationCall
			srv := newDeviceAuthorizationServer(t, &got)

			_, err := DeviceAuthorization(context.Background(), []string{"openid"}, newDeviceRP(srv, tt.style, tt.signer), tt.authFn)
			require.NoError(t, err)

			// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
			assert.Equal(t, 1, got.authMethods(), "authentication methods in the request")
			assert.Equal(t, tt.wantBasic, got.hasBasic, "Authorization header")
			assert.Equal(t, tt.wantSecret, got.form.Get("client_secret") != "", "client_secret in the form")
			assert.Equal(t, tt.wantAssertion, got.form.Get("client_assertion") != "", "client_assertion in the form")
			if tt.wantBasic {
				assert.Equal(t, "client", got.basicUser)
				assert.Equal(t, "secret", got.basicPass)
			}
			assert.Equal(t, "client", got.form.Get("client_id"))
		})
	}
}

// A caller that only adds form fields, such as a PKCE challenge, still has the
// client authenticated with the secret in the form.
func TestDeviceAuthorizationKeepsFormAuthorization(t *testing.T) {
	var got deviceAuthorizationCall
	srv := newDeviceAuthorizationServer(t, &got)
	authFn := httphelper.FormAuthorization(func(form url.Values) {
		form.Set("code_challenge", "challenge")
	})

	_, err := DeviceAuthorization(context.Background(), []string{"openid"}, newDeviceRP(srv, oauth2.AuthStyleAutoDetect, nil), authFn)
	require.NoError(t, err)

	assert.Equal(t, "challenge", got.form.Get("code_challenge"))
	assert.Equal(t, "secret", got.form.Get("client_secret"))
	assert.False(t, got.hasBasic)
}

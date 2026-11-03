package cli

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestCallbackServerConfig(t *testing.T) {
	tests := []struct {
		name         string
		redirectURI  string
		callbackPath string
		port         string
		wantListen   string
		wantLoginURL string
		wantErr      bool
	}{
		{
			name:         "IPv4 loopback",
			redirectURI:  "http://127.0.0.1:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantListen:   "127.0.0.1:3000",
			wantLoginURL: "http://127.0.0.1:3000/login",
		},
		{
			name:         "IPv6 loopback",
			redirectURI:  "http://[::1]:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantListen:   "[::1]:3000",
			wantLoginURL: "http://[::1]:3000/login",
		},
		{
			name:         "localhost compatibility",
			redirectURI:  "http://localhost:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantListen:   ":3000",
			wantLoginURL: "http://localhost:3000/login",
		},
		{
			name:         "missing port",
			redirectURI:  "http://127.0.0.1/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "port mismatch",
			redirectURI:  "http://127.0.0.1:3001/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "HTTPS",
			redirectURI:  "https://127.0.0.1:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "remote host",
			redirectURI:  "http://example.com:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "localhost lookalike",
			redirectURI:  "http://localhost.attacker.com:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "IPv4 lookalike",
			redirectURI:  "http://127.0.0.1.attacker.com:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "callback path mismatch",
			redirectURI:  "http://127.0.0.1:3000/callback",
			callbackPath: "/other",
			port:         "3000",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listenAddress, loginURL, err := callbackServerConfig(tt.redirectURI, tt.callbackPath, tt.port)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantListen, listenAddress)
			assert.Equal(t, tt.wantLoginURL, loginURL)
		})
	}
}

func TestCodeFlowHandlers(t *testing.T) {
	tests := []struct {
		name         string
		opts         []CodeFlowOpt
		wantAudience string
		wantResource string
		wantPageBody string
	}{
		{
			name:         "defaults",
			wantPageBody: defaultSuccessHTML,
		},
		{
			name: "with options",
			opts: []CodeFlowOpt{
				WithAuthURLParams(rp.WithURLParam("audience", "https://api.example.com")),
				WithCodeExchangeParams(rp.WithURLParam("resource", "https://api.example.com")),
				WithSuccessHTML(`<body onload="window.close()">You may close this window</body>`),
			},
			wantAudience: "https://api.example.com",
			wantResource: "https://api.example.com",
			wantPageBody: `<body onload="window.close()">You may close this window</body>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tokenForm url.Values
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				tokenForm = r.PostForm
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
			}))
			defer tokenServer.Close()

			key := []byte("test1234test1234test1234test1234")
			relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
				ClientID:     "client",
				ClientSecret: "secret",
				RedirectURL:  "http://127.0.0.1:3000/callback",
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://op.example.com/authorize",
					TokenURL: tokenServer.URL,
				},
			}, rp.WithCookieHandler(httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())))
			require.NoError(t, err)

			tokenChan := make(chan *oidc.Tokens[*oidc.IDTokenClaims], 1)
			login, callback := codeFlowHandlers(relyingParty, func() string { return "state1" }, tokenChan, tt.opts...)

			loginResp := httptest.NewRecorder()
			login.ServeHTTP(loginResp, httptest.NewRequest(http.MethodGet, "/login", nil))
			require.Equal(t, http.StatusFound, loginResp.Code)
			authURL, err := url.Parse(loginResp.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "state1", authURL.Query().Get("state"))
			assert.Equal(t, tt.wantAudience, authURL.Query().Get("audience"))

			callbackReq := httptest.NewRequest(http.MethodGet, "/callback?code=code1&state=state1", nil)
			for _, cookie := range loginResp.Result().Cookies() {
				callbackReq.AddCookie(cookie)
			}
			callbackResp := httptest.NewRecorder()
			callback.ServeHTTP(callbackResp, callbackReq)

			assert.Equal(t, tt.wantPageBody, callbackResp.Body.String())
			assert.Equal(t, "code1", tokenForm.Get("code"))
			assert.Equal(t, tt.wantResource, tokenForm.Get("resource"))
			select {
			case tokens := <-tokenChan:
				assert.Equal(t, "access", tokens.AccessToken)
			default:
				t.Fatal("no tokens sent to the channel")
			}
		})
	}
}

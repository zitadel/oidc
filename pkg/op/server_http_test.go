package op

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/schema"
	"golang.org/x/exp/slog"
)

type testClient struct {
	id              string
	appType         ApplicationType
	authMethod      oidc.AuthMethod
	accessTokenType AccessTokenType
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	devMode         bool
}

func newClient(kind string) *testClient {
	client := &testClient{
		id: kind,
	}

	switch kind {
	case "web_client":
		client.appType = ApplicationTypeWeb
		client.authMethod = oidc.AuthMethodBasic
		client.accessTokenType = AccessTokenTypeBearer
		client.responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
	case "native_client":
		client.appType = ApplicationTypeNative
		client.authMethod = oidc.AuthMethodNone
		client.accessTokenType = AccessTokenTypeBearer
		client.responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
	case "useragent_client":
		client.appType = ApplicationTypeUserAgent
		client.authMethod = oidc.AuthMethodBasic
		client.accessTokenType = AccessTokenTypeJWT
		client.responseTypes = []oidc.ResponseType{oidc.ResponseTypeIDToken}
	}
	return client
}

func (c *testClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://registered.com/callback",
		"http://localhost:9999/callback",
		"custom://callback",
	}
}

func (c *testClient) PostLogoutRedirectURIs() []string {
	return []string{}
}

func (c *testClient) LoginURL(id string) string {
	return "login?id=" + id
}

func (c *testClient) ApplicationType() ApplicationType {
	return c.appType
}

func (c *testClient) AuthMethod() oidc.AuthMethod {
	return c.authMethod
}

func (c *testClient) GetID() string {
	return c.id
}

func (c *testClient) AccessTokenLifetime() time.Duration {
	return 5 * time.Minute
}

func (c *testClient) IDTokenLifetime() time.Duration {
	return 5 * time.Minute
}

func (c *testClient) AccessTokenType() AccessTokenType {
	return c.accessTokenType
}

func (c *testClient) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}

func (c *testClient) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *testClient) DevMode() bool {
	return c.devMode
}

func (c *testClient) AllowedScopes() []string {
	return nil
}

func (c *testClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *testClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *testClient) IsScopeAllowed(scope string) bool {
	return false
}

func (c *testClient) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

func (c *testClient) ClockSkew() time.Duration {
	return 0
}

var testDecoder = func() *schema.Decoder {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	return decoder
}()

var testWebServer = &webServer{
	server:    UnimplementedServer{},
	endpoints: *DefaultEndpoints,
	decoder:   testDecoder,
	logger:    slog.Default(),
}

func Test_webServer_verifyRequestClient(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    Client
		wantErr error
	}{
		{
			name:    "parse form error",
			decoder: testDecoder,
			r:       httptest.NewRequest("POST", "/", bytes.NewReader(make([]byte, 11<<20))),
			wantErr: oidc.ErrInvalidRequest().WithDescription("error parsing form"),
		},
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest("POST", "/", strings.NewReader("foo=bar")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("error decoding form"),
		},
		{
			name:    "basic auth, client_id error",
			decoder: testDecoder,
			r: func() *http.Request {
				r := httptest.NewRequest("POST", "/", strings.NewReader("foo=bar"))
				r.SetBasicAuth(`%%%`, "secret")
				return r
			}(),
			wantErr: oidc.ErrInvalidClient().WithDescription("invalid basic auth header"),
		},
		{
			name:    "basic auth, client_secret error",
			decoder: testDecoder,
			r: func() *http.Request {
				r := httptest.NewRequest("POST", "/", strings.NewReader("foo=bar"))
				r.SetBasicAuth("web", `%%%`)
				return r
			}(),
			wantErr: oidc.ErrInvalidClient().WithDescription("invalid basic auth header"),
		},
		{
			name:    "missing client id and assertion",
			decoder: testDecoder,
			r:       httptest.NewRequest("POST", "/", strings.NewReader("foo=bar")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client_id or client_assertion must be provided"),
		},
		{
			name:    "wrong assertion type",
			decoder: testDecoder,
			r:       httptest.NewRequest("POST", "/", strings.NewReader("foo=bar&client_assertion=xxx&client_assertion_type=wrong")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("invalid client_assertion_type wrong"),
		},
		{
			name:    "unimplemented verify client called",
			decoder: testDecoder,
			r:       httptest.NewRequest("POST", "/", strings.NewReader("foo=bar&client_id=web")),
			wantErr: StatusError{
				parent:     oidc.ErrServerError().WithDescription("/ not implemented on this server"),
				statusCode: UnimplementedStatusCode,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &webServer{
				server:  UnimplementedServer{},
				decoder: tt.decoder,
				logger:  slog.Default(),
			}
			tt.r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			got, err := s.verifyRequestClient(tt.r)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

type authRequestVerifier struct {
	UnimplementedServer
	client Client
}

func (s *authRequestVerifier) VerifyAuthRequest(ctx context.Context, r *Request[oidc.AuthRequest]) (*ClientRequest[oidc.AuthRequest], error) {
	if s.client == nil {
		return nil, oidc.ErrServerError()
	}
	return &ClientRequest[oidc.AuthRequest]{
		Request: r,
		Client:  s.client,
	}, nil
}

func Test_webServer_authorizeHandler(t *testing.T) {
	type fields struct {
		server  Server
		decoder httphelper.Decoder
	}
	tests := []struct {
		name       string
		fields     fields
		r          *http.Request
		wantStatus int
		wantBody   string
	}{
		{
			name: "decoder error",
			fields: fields{
				server:  &authRequestVerifier{},
				decoder: schema.NewDecoder(),
			},
			r:          httptest.NewRequest("POST", "/authorize", bytes.NewBufferString("foo=bar")),
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
		},
		{
			name: "authorize error",
			fields: fields{
				server:  &authRequestVerifier{},
				decoder: testDecoder,
			},
			r:          httptest.NewRequest("POST", "/authorize", bytes.NewBufferString("foo=bar")),
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"server_error"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &webServer{
				server:  tt.fields.server,
				decoder: tt.fields.decoder,
				logger:  slog.Default(),
			}
			tt.r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			s.authorizeHandler(w, tt.r)
			res := w.Result()
			assert.Equal(t, tt.wantStatus, res.StatusCode)
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			assert.JSONEq(t, tt.wantBody, string(body))
		})
	}
}

func Test_webServer_authorize(t *testing.T) {
	type args struct {
		ctx context.Context
		r   *Request[oidc.AuthRequest]
	}
	tests := []struct {
		name    string
		server  Server
		args    args
		want    *Redirect
		wantErr error
	}{
		{
			name:   "verify error",
			server: &authRequestVerifier{},
			args: args{
				ctx: context.Background(),
				r: &Request[oidc.AuthRequest]{
					Data: &oidc.AuthRequest{
						Scopes:       oidc.SpaceDelimitedArray{"openid"},
						ResponseType: oidc.ResponseTypeCode,
						ClientID:     "web",
						RedirectURI:  "https://registered.com/callback",
						MaxAge:       gu.Ptr[uint](300),
					},
				},
			},
			wantErr: oidc.ErrServerError(),
		},
		{
			name: "missing redirect",
			server: &authRequestVerifier{
				client: newClient("web_client"),
			},
			args: args{
				ctx: context.Background(),
				r: &Request[oidc.AuthRequest]{
					Data: &oidc.AuthRequest{
						Scopes:       oidc.SpaceDelimitedArray{"openid"},
						ResponseType: oidc.ResponseTypeCode,
						ClientID:     "web",
						MaxAge:       gu.Ptr[uint](300),
					},
				},
			},
			wantErr: ErrAuthReqMissingRedirectURI,
		},
		{
			name: "invalid prompt",
			server: &authRequestVerifier{
				client: newClient("web_client"),
			},
			args: args{
				ctx: context.Background(),
				r: &Request[oidc.AuthRequest]{
					Data: &oidc.AuthRequest{
						Scopes:       oidc.SpaceDelimitedArray{"openid"},
						ResponseType: oidc.ResponseTypeCode,
						ClientID:     "web",
						RedirectURI:  "https://registered.com/callback",
						MaxAge:       gu.Ptr[uint](300),
						Prompt:       []string{oidc.PromptNone, oidc.PromptLogin},
					},
				},
			},
			wantErr: oidc.ErrInvalidRequest().WithDescription("The prompt parameter `none` must only be used as a single value"),
		},
		{
			name: "missing scopes",
			server: &authRequestVerifier{
				client: newClient("web_client"),
			},
			args: args{
				ctx: context.Background(),
				r: &Request[oidc.AuthRequest]{
					Data: &oidc.AuthRequest{
						ResponseType: oidc.ResponseTypeCode,
						ClientID:     "web",
						RedirectURI:  "https://registered.com/callback",
						MaxAge:       gu.Ptr[uint](300),
						Prompt:       []string{oidc.PromptNone},
					},
				},
			},
			wantErr: oidc.ErrInvalidRequest().
				WithDescription("The scope of your request is missing. Please ensure some scopes are requested. " +
					"If you have any questions, you may contact the administrator of the application."),
		},
		{
			name: "invalid redirect",
			server: &authRequestVerifier{
				client: newClient("web_client"),
			},
			args: args{
				ctx: context.Background(),
				r: &Request[oidc.AuthRequest]{
					Data: &oidc.AuthRequest{
						Scopes:       oidc.SpaceDelimitedArray{"openid"},
						ResponseType: oidc.ResponseTypeCode,
						ClientID:     "web",
						RedirectURI:  "https://example.com/callback",
						MaxAge:       gu.Ptr[uint](300),
						Prompt:       []string{oidc.PromptNone},
					},
				},
			},
			wantErr: oidc.ErrInvalidRequestRedirectURI().
				WithDescription("The requested redirect_uri is missing in the client configuration. " +
					"If you have any questions, you may contact the administrator of the application."),
		},
		{
			name: "invalid response type",
			server: &authRequestVerifier{
				client: newClient("web_client"),
			},
			args: args{
				ctx: context.Background(),
				r: &Request[oidc.AuthRequest]{
					Data: &oidc.AuthRequest{
						Scopes:       oidc.SpaceDelimitedArray{"openid"},
						ResponseType: oidc.ResponseTypeIDToken,
						ClientID:     "web",
						RedirectURI:  "https://registered.com/callback",
						MaxAge:       gu.Ptr[uint](300),
						Prompt:       []string{oidc.PromptNone},
					},
				},
			},
			wantErr: oidc.ErrUnauthorizedClient().WithDescription("The requested response type is missing in the client configuration. " +
				"If you have any questions, you may contact the administrator of the application."),
		},
		{
			name: "unimplemented Authorize called",
			server: &authRequestVerifier{
				client: newClient("web_client"),
			},
			args: args{
				ctx: context.Background(),
				r: &Request[oidc.AuthRequest]{
					URL: &url.URL{
						Path: "/authorize",
					},
					Data: &oidc.AuthRequest{
						Scopes:       oidc.SpaceDelimitedArray{"openid"},
						ResponseType: oidc.ResponseTypeCode,
						ClientID:     "web",
						RedirectURI:  "https://registered.com/callback",
						MaxAge:       gu.Ptr[uint](300),
						Prompt:       []string{oidc.PromptNone},
					},
				},
			},
			wantErr: StatusError{
				parent:     oidc.ErrServerError().WithDescription("/authorize not implemented on this server"),
				statusCode: UnimplementedStatusCode,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &webServer{
				server:  tt.server,
				decoder: testDecoder,
				logger:  slog.Default(),
			}
			got, err := s.authorize(tt.args.ctx, tt.args.r)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

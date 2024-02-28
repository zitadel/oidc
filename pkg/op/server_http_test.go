package op

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/schema"
)

func TestRegisterServer(t *testing.T) {
	server := UnimplementedServer{}
	endpoints := Endpoints{
		Authorization: &Endpoint{
			path: "/auth",
		},
	}
	decoder := schema.NewDecoder()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	h := RegisterServer(server, endpoints,
		WithDecoder(decoder),
		WithFallbackLogger(logger),
	)
	got := h.(*webServer)
	assert.Equal(t, got.server, server)
	assert.Equal(t, got.endpoints, endpoints)
	assert.Equal(t, got.decoder, decoder)
	assert.Equal(t, got.logger, logger)
}

type testClient struct {
	id              string
	appType         ApplicationType
	authMethod      oidc.AuthMethod
	accessTokenType AccessTokenType
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	devMode         bool
}

type clientType string

const (
	clientTypeWeb       clientType = "web"
	clientTypeNative    clientType = "native"
	clientTypeUserAgent clientType = "useragent"
)

func newClient(kind clientType) *testClient {
	client := &testClient{
		id: string(kind),
	}

	switch kind {
	case clientTypeWeb:
		client.appType = ApplicationTypeWeb
		client.authMethod = oidc.AuthMethodBasic
		client.accessTokenType = AccessTokenTypeBearer
		client.responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
	case clientTypeNative:
		client.appType = ApplicationTypeNative
		client.authMethod = oidc.AuthMethodNone
		client.accessTokenType = AccessTokenTypeBearer
		client.responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
	case clientTypeUserAgent:
		client.appType = ApplicationTypeUserAgent
		client.authMethod = oidc.AuthMethodBasic
		client.accessTokenType = AccessTokenTypeJWT
		client.responseTypes = []oidc.ResponseType{oidc.ResponseTypeIDToken}
	default:
		panic(fmt.Errorf("invalid client type %s", kind))
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

type requestVerifier struct {
	UnimplementedServer
	client Client
}

func (s *requestVerifier) VerifyAuthRequest(ctx context.Context, r *Request[oidc.AuthRequest]) (*ClientRequest[oidc.AuthRequest], error) {
	if s.client == nil {
		return nil, oidc.ErrServerError()
	}
	return &ClientRequest[oidc.AuthRequest]{
		Request: r,
		Client:  s.client,
	}, nil
}

func (s *requestVerifier) VerifyClient(ctx context.Context, r *Request[ClientCredentials]) (Client, error) {
	if s.client == nil {
		return nil, oidc.ErrServerError()
	}
	return s.client, nil
}

var testDecoder = func() *schema.Decoder {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	return decoder
}()

type webServerResult struct {
	wantStatus int
	wantBody   string
}

func runWebServerTest(t *testing.T, handler http.HandlerFunc, r *http.Request, want webServerResult) {
	t.Helper()
	if r.Method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	handler(w, r)
	res := w.Result()
	assert.Equal(t, want.wantStatus, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.JSONEq(t, want.wantBody, string(body))
}

func Test_webServer_withClient(t *testing.T) {
	tests := []struct {
		name string
		r    *http.Request
		want webServerResult
	}{
		{
			name: "parse error",
			r:    httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 11<<20))),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error parsing form"}`,
			},
		},
		{
			name: "invalid grant type",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=native&grant_type=bad&foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unauthorized_client", "error_description":"grant_type \"bad\" not allowed"}`,
			},
		},
		{
			name: "no grant type",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=native&foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusOK,
				wantBody:   `{"foo":"bar"}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &webServer{
				server: &requestVerifier{
					client: newClient(clientTypeNative),
				},
				decoder: testDecoder,
				logger:  slog.Default(),
			}
			handler := func(w http.ResponseWriter, r *http.Request, client Client) {
				fmt.Fprintf(w, `{"foo":%q}`, r.FormValue("foo"))
			}
			runWebServerTest(t, s.withClient(handler), tt.r, tt.want)
		})
	}
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
			r:       httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 11<<20))),
			wantErr: oidc.ErrInvalidRequest().WithDescription("error parsing form"),
		},
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("error decoding form"),
		},
		{
			name:    "basic auth, client_id error",
			decoder: testDecoder,
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar"))
				r.SetBasicAuth(`%%%`, "secret")
				return r
			}(),
			wantErr: oidc.ErrInvalidClient().WithDescription("invalid basic auth header"),
		},
		{
			name:    "basic auth, client_secret error",
			decoder: testDecoder,
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar"))
				r.SetBasicAuth("web", `%%%`)
				return r
			}(),
			wantErr: oidc.ErrInvalidClient().WithDescription("invalid basic auth header"),
		},
		{
			name:    "missing client id and assertion",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client_id or client_assertion must be provided"),
		},
		{
			name:    "wrong assertion type",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar&client_assertion=xxx&client_assertion_type=wrong")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("invalid client_assertion_type wrong"),
		},
		{
			name:    "unimplemented verify client called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar&client_id=web")),
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

func Test_webServer_authorizeHandler(t *testing.T) {
	type fields struct {
		server  Server
		decoder httphelper.Decoder
	}
	tests := []struct {
		name   string
		fields fields
		r      *http.Request
		want   webServerResult
	}{
		{
			name: "decoder error",
			fields: fields{
				server:  &requestVerifier{},
				decoder: schema.NewDecoder(),
			},
			r: httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name: "server error",
			fields: fields{
				server:  &requestVerifier{},
				decoder: testDecoder,
			},
			r: httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusInternalServerError,
				wantBody:   `{"error":"server_error"}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &webServer{
				server:  tt.fields.server,
				decoder: tt.fields.decoder,
				logger:  slog.Default(),
			}
			runWebServerTest(t, s.authorizeHandler, tt.r, tt.want)
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
			server: &requestVerifier{},
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
			server: &requestVerifier{
				client: newClient(clientTypeWeb),
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
			server: &requestVerifier{
				client: newClient(clientTypeWeb),
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
			server: &requestVerifier{
				client: newClient(clientTypeWeb),
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
			server: &requestVerifier{
				client: newClient(clientTypeWeb),
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
			server: &requestVerifier{
				client: newClient(clientTypeWeb),
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
			server: &requestVerifier{
				client: newClient(clientTypeWeb),
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

func Test_webServer_deviceAuthorizationHandler(t *testing.T) {
	type fields struct {
		server  Server
		decoder httphelper.Decoder
	}
	tests := []struct {
		name   string
		fields fields
		r      *http.Request
		want   webServerResult
	}{
		{
			name: "decoder error",
			fields: fields{
				server:  &requestVerifier{},
				decoder: schema.NewDecoder(),
			},
			r: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name: "unimplemented DeviceAuthorization called",
			fields: fields{
				server: &requestVerifier{
					client: newClient(clientTypeNative),
				},
				decoder: testDecoder,
			},
			r: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=native_client")),
			want: webServerResult{
				wantStatus: UnimplementedStatusCode,
				wantBody:   `{"error":"server_error", "error_description":"/ not implemented on this server"}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &webServer{
				server:  tt.fields.server,
				decoder: tt.fields.decoder,
				logger:  slog.Default(),
			}
			client := newClient(clientTypeUserAgent)
			runWebServerClientTest(t, s.deviceAuthorizationHandler, tt.r, client, tt.want)
		})
	}
}

func Test_webServer_tokensHandler(t *testing.T) {
	tests := []struct {
		name string
		r    *http.Request
		want webServerResult
	}{
		{
			name: "parse form error",
			r:    httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 11<<20))),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error parsing form"}`,
			},
		},
		{
			name: "missing grant type",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"grant_type missing"}`,
			},
		},
		{
			name: "invalid grant type",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("grant_type=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unsupported_grant_type", "error_description":"bar not supported"}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &webServer{
				logger: slog.Default(),
			}
			runWebServerTest(t, s.tokensHandler, tt.r, tt.want)
		})
	}
}

func Test_webServer_jwtProfileHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "assertion missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"assertion missing"}`,
			},
		},
		{
			name:    "unimplemented JWTProfile called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("assertion=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unsupported_grant_type", "error_description":"urn:ietf:params:oauth:grant-type:jwt-bearer not supported"}`,
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
			runWebServerTest(t, s.jwtProfileHandler, tt.r, tt.want)
		})
	}
}

func runWebServerClientTest(t *testing.T, handler func(http.ResponseWriter, *http.Request, Client), r *http.Request, client Client, want webServerResult) {
	t.Helper()
	runWebServerTest(t, func(client Client) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			handler(w, r, client)
		}
	}(client), r, want)
}

func Test_webServer_codeExchangeHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "code missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"code missing"}`,
			},
		},
		{
			name:    "redirect missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("code=123")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"redirect_uri missing"}`,
			},
		},
		{
			name:    "unimplemented CodeExchange called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("code=123&redirect_uri=https://example.com/callback")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unsupported_grant_type", "error_description":"authorization_code not supported"}`,
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
			client := newClient(clientTypeUserAgent)
			runWebServerClientTest(t, s.codeExchangeHandler, tt.r, client, tt.want)
		})
	}
}

func Test_webServer_refreshTokenHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "refresh token missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"refresh_token missing"}`,
			},
		},
		{
			name:    "unimplemented RefreshToken called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("refresh_token=xxx")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unsupported_grant_type", "error_description":"refresh_token not supported"}`,
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
			client := newClient(clientTypeUserAgent)
			runWebServerClientTest(t, s.refreshTokenHandler, tt.r, client, tt.want)
		})
	}
}

func Test_webServer_tokenExchangeHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "subject token missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"subject_token missing"}`,
			},
		},
		{
			name:    "subject token type missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("subject_token=xxx")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"subject_token_type missing"}`,
			},
		},
		{
			name:    "subject token type unsupported",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("subject_token=xxx&subject_token_type=foo")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"subject_token_type is not supported"}`,
			},
		},
		{
			name:    "unsupported requested token type",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("subject_token=xxx&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=foo")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"requested_token_type is not supported"}`,
			},
		},
		{
			name:    "unsupported actor token type",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("subject_token=xxx&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&actor_token_type=foo")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"actor_token_type is not supported"}`,
			},
		},
		{
			name:    "unimplemented TokenExchange called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("subject_token=xxx&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&actor_token_type=urn:ietf:params:oauth:token-type:access_token")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unsupported_grant_type", "error_description":"urn:ietf:params:oauth:grant-type:token-exchange not supported"}`,
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
			client := newClient(clientTypeUserAgent)
			runWebServerClientTest(t, s.tokenExchangeHandler, tt.r, client, tt.want)
		})
	}
}

func Test_webServer_clientCredentialsHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		client  Client
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			client:  newClient(clientTypeUserAgent),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "public client",
			decoder: testDecoder,
			client:  newClient(clientTypeNative),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_client", "error_description":"client must be authenticated"}`,
			},
		},
		{
			name:    "unimplemented ClientCredentialsExchange called",
			decoder: testDecoder,
			client:  newClient(clientTypeUserAgent),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unsupported_grant_type", "error_description":"client_credentials not supported"}`,
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
			runWebServerClientTest(t, s.clientCredentialsHandler, tt.r, tt.client, tt.want)
		})
	}
}

func Test_webServer_deviceTokenHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "device code missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"device_code missing"}`,
			},
		},
		{
			name:    "unimplemented DeviceToken called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("device_code=xxx")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"unsupported_grant_type", "error_description":"urn:ietf:params:oauth:grant-type:device_code not supported"}`,
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
			client := newClient(clientTypeUserAgent)
			runWebServerClientTest(t, s.deviceTokenHandler, tt.r, client, tt.want)
		})
	}
}

func Test_webServer_introspectionHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "public client",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=123")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_client", "error_description":"client must be authenticated"}`,
			},
		},
		{
			name:    "token missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=123&client_secret=SECRET")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"token missing"}`,
			},
		},
		{
			name:    "unimplemented Introspect called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=123&client_secret=SECRET&token=xxx")),
			want: webServerResult{
				wantStatus: UnimplementedStatusCode,
				wantBody:   `{"error":"server_error", "error_description":"/ not implemented on this server"}`,
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
			runWebServerTest(t, s.introspectionHandler, tt.r, tt.want)
		})
	}
}

func Test_webServer_userInfoHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "access token missing",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusUnauthorized,
				wantBody:   `{"error":"invalid_request", "error_description":"access token missing"}`,
			},
		},
		{
			name:    "unimplemented UserInfo called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("access_token=xxx")),
			want: webServerResult{
				wantStatus: UnimplementedStatusCode,
				wantBody:   `{"error":"server_error", "error_description":"/ not implemented on this server"}`,
			},
		},
		{
			name:    "bearer",
			decoder: testDecoder,
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("authorization", strings.Join([]string{"Bearer", "xxx"}, " "))
				return r
			}(),
			want: webServerResult{
				wantStatus: UnimplementedStatusCode,
				wantBody:   `{"error":"server_error", "error_description":"/ not implemented on this server"}`,
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
			runWebServerTest(t, s.userInfoHandler, tt.r, tt.want)
		})
	}
}

func Test_webServer_revocationHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		client  Client
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			client:  newClient(clientTypeWeb),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "token missing",
			decoder: testDecoder,
			client:  newClient(clientTypeWeb),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"token missing"}`,
			},
		},
		{
			name:    "unimplemented Revocation called, confidential client",
			decoder: testDecoder,
			client:  newClient(clientTypeWeb),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=xxx")),
			want: webServerResult{
				wantStatus: UnimplementedStatusCode,
				wantBody:   `{"error":"server_error", "error_description":"/ not implemented on this server"}`,
			},
		},
		{
			name:    "unimplemented Revocation called, public client",
			decoder: testDecoder,
			client:  newClient(clientTypeNative),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=xxx")),
			want: webServerResult{
				wantStatus: UnimplementedStatusCode,
				wantBody:   `{"error":"server_error", "error_description":"/ not implemented on this server"}`,
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
			runWebServerClientTest(t, s.revocationHandler, tt.r, tt.client, tt.want)
		})
	}
}

func Test_webServer_endSessionHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "decoder error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error decoding form"}`,
			},
		},
		{
			name:    "unimplemented EndSession called",
			decoder: testDecoder,
			r:       httptest.NewRequest(http.MethodPost, "/", strings.NewReader("id_token_hint=xxx")),
			want: webServerResult{
				wantStatus: UnimplementedStatusCode,
				wantBody:   `{"error":"server_error", "error_description":"/ not implemented on this server"}`,
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
			runWebServerTest(t, s.endSessionHandler, tt.r, tt.want)
		})
	}
}

func Test_webServer_simpleHandler(t *testing.T) {
	tests := []struct {
		name    string
		decoder httphelper.Decoder
		method  func(context.Context, *Request[struct{}]) (*Response, error)
		r       *http.Request
		want    webServerResult
	}{
		{
			name:    "parse error",
			decoder: schema.NewDecoder(),
			r:       httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 11<<20))),
			want: webServerResult{
				wantStatus: http.StatusBadRequest,
				wantBody:   `{"error":"invalid_request", "error_description":"error parsing form"}`,
			},
		},
		{
			name:    "method error",
			decoder: schema.NewDecoder(),
			method: func(ctx context.Context, r *Request[struct{}]) (*Response, error) {
				return nil, io.ErrClosedPipe
			},
			r: httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(make([]byte, 11<<20))),
			want: webServerResult{
				wantStatus: http.StatusInternalServerError,
				wantBody:   `{"error":"server_error", "error_description":"io: read/write on closed pipe"}`,
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
			runWebServerTest(t, simpleHandler(s, tt.method), tt.r, tt.want)
		})
	}
}

func Test_decodeRequest(t *testing.T) {
	type dst struct {
		A string `schema:"a"`
		B string `schema:"b"`
	}
	type args struct {
		r        *http.Request
		postOnly bool
	}
	tests := []struct {
		name    string
		args    args
		want    *dst
		wantErr error
	}{
		{
			name: "parse error",
			args: args{
				r: httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 11<<20))),
			},
			wantErr: oidc.ErrInvalidRequest().WithDescription("error parsing form"),
		},
		{
			name: "decode error",
			args: args{
				r: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar")),
			},
			wantErr: oidc.ErrInvalidRequest().WithDescription("error decoding form"),
		},
		{
			name: "success, get",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/?a=b&b=a", nil),
			},
			want: &dst{
				A: "b",
				B: "a",
			},
		},
		{
			name: "success, post only",
			args: args{
				r:        httptest.NewRequest(http.MethodPost, "/?b=a", strings.NewReader("a=b&")),
				postOnly: true,
			},
			want: &dst{
				A: "b",
			},
		},
		{
			name: "success, post mixed",
			args: args{
				r:        httptest.NewRequest(http.MethodPost, "/?b=a", strings.NewReader("a=b&")),
				postOnly: false,
			},
			want: &dst{
				A: "b",
				B: "a",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.r.Method == http.MethodPost {
				tt.args.r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			got, err := decodeRequest[dst](schema.NewDecoder(), tt.args.r, tt.args.postOnly)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

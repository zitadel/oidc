package op_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
	"github.com/zitadel/schema"
)

func TestAuthorize(t *testing.T) {
	tests := []struct {
		name   string
		req    *http.Request
		expect func(a *mock.MockAuthorizerMockRecorder)
	}{
		{
			name: "parse error", // used to panic, see issue #315
			req:  httptest.NewRequest(http.MethodPost, "/?;", nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			authorizer := mock.NewMockAuthorizer(gomock.NewController(t))

			expect := authorizer.EXPECT()
			expect.Decoder().Return(schema.NewDecoder())
			expect.Logger().Return(slog.Default())

			if tt.expect != nil {
				tt.expect(expect)
			}

			op.Authorize(w, tt.req, authorizer)
		})
	}
}

func TestParseAuthorizeRequest(t *testing.T) {
	type args struct {
		r       *http.Request
		decoder httphelper.Decoder
	}
	type res struct {
		want *oidc.AuthRequest
		err  bool
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"parsing form error",
			args{
				&http.Request{URL: &url.URL{RawQuery: "invalid=%%param"}},
				schema.NewDecoder(),
			},
			res{
				nil,
				true,
			},
		},
		{
			"decoding error",
			args{
				&http.Request{URL: &url.URL{RawQuery: "unknown=value"}},
				func() httphelper.Decoder {
					decoder := schema.NewDecoder()
					decoder.IgnoreUnknownKeys(false)
					return decoder
				}(),
			},
			res{
				nil,
				true,
			},
		},
		{
			"parsing ok",
			args{
				&http.Request{URL: &url.URL{RawQuery: "scope=openid"}},
				func() httphelper.Decoder {
					decoder := schema.NewDecoder()
					decoder.IgnoreUnknownKeys(false)
					return decoder
				}(),
			},
			res{
				&oidc.AuthRequest{Scopes: oidc.SpaceDelimitedArray{"openid"}},
				false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.ParseAuthorizeRequest(tt.args.r, tt.args.decoder)
			if (err != nil) != tt.res.err {
				t.Errorf("ParseAuthorizeRequest() error = %v, wantErr %v", err, tt.res.err)
			}
			if !reflect.DeepEqual(got, tt.res.want) {
				t.Errorf("ParseAuthorizeRequest() got = %v, want %v", got, tt.res.want)
			}
		})
	}
}

func TestValidateAuthRequest(t *testing.T) {
	type args struct {
		authRequest *oidc.AuthRequest
		storage     op.Storage
		verifier    *op.IDTokenHintVerifier
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			"scope missing fails",
			args{&oidc.AuthRequest{}, mock.NewMockStorageExpectValidClientID(t), nil},
			oidc.ErrInvalidRequest(),
		},
		{
			"response_type missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"openid"}}, mock.NewMockStorageExpectValidClientID(t), nil},
			oidc.ErrInvalidRequest(),
		},
		{
			"client_id missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"openid"}, ResponseType: oidc.ResponseTypeCode}, mock.NewMockStorageExpectValidClientID(t), nil},
			oidc.ErrInvalidRequest(),
		},
		{
			"redirect_uri missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"openid"}, ResponseType: oidc.ResponseTypeCode, ClientID: "client_id"}, mock.NewMockStorageExpectValidClientID(t), nil},
			oidc.ErrInvalidRequest(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := op.ValidateAuthRequest(context.TODO(), tt.args.authRequest, tt.args.storage, tt.args.verifier)
			if tt.wantErr == nil && err != nil {
				t.Errorf("ValidateAuthRequest() unexpected error = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateAuthRequest() unexpected error = %v, want = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAuthReqPrompt(t *testing.T) {
	type args struct {
		prompts []string
		maxAge  *uint
	}
	type res struct {
		maxAge *uint
		err    error
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"no prompts and maxAge, ok",
			args{
				nil,
				nil,
			},
			res{
				nil,
				nil,
			},
		},
		{
			"no prompts but maxAge, ok",
			args{
				nil,
				oidc.NewMaxAge(10),
			},
			res{
				oidc.NewMaxAge(10),
				nil,
			},
		},
		{
			"prompt none, ok",
			args{
				[]string{"none"},
				oidc.NewMaxAge(10),
			},
			res{
				oidc.NewMaxAge(10),
				nil,
			},
		},
		{
			"prompt none with others, err",
			args{
				[]string{"none", "login"},
				oidc.NewMaxAge(10),
			},
			res{
				nil,
				oidc.ErrInvalidRequest(),
			},
		},
		{
			"prompt login, ok",
			args{
				[]string{"login"},
				nil,
			},
			res{
				oidc.NewMaxAge(0),
				nil,
			},
		},
		{
			"prompt login with maxAge, ok",
			args{
				[]string{"login"},
				oidc.NewMaxAge(10),
			},
			res{
				oidc.NewMaxAge(0),
				nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxAge, err := op.ValidateAuthReqPrompt(tt.args.prompts, tt.args.maxAge)
			if tt.res.err == nil && err != nil {
				t.Errorf("ValidateAuthRequest() unexpected error = %v", err)
			}
			if tt.res.err != nil && !errors.Is(err, tt.res.err) {
				t.Errorf("ValidateAuthRequest() unexpected error = %v, want = %v", err, tt.res.err)
			}
			assert.Equal(t, tt.res.maxAge, maxAge)
		})
	}
}

func TestValidateAuthReqScopes(t *testing.T) {
	type args struct {
		client op.Client
		scopes []string
	}
	type res struct {
		err    bool
		scopes []string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"scopes missing fails",
			args{},
			res{
				err: true,
			},
		},
		{
			"scope ok",
			args{
				mock.NewClientExpectAny(t, op.ApplicationTypeWeb),
				[]string{"openid"},
			},
			res{
				scopes: []string{"openid"},
			},
		},
		{
			"scope with drop ok",
			args{
				mock.NewClientExpectAny(t, op.ApplicationTypeWeb),
				[]string{"openid", "email", "unknown"},
			},
			res{
				scopes: []string{"openid", "email"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes, err := op.ValidateAuthReqScopes(tt.args.client, tt.args.scopes)
			if (err != nil) != tt.res.err {
				t.Errorf("ValidateAuthReqScopes() error = %v, wantErr %v", err, tt.res.err)
			}
			assert.ElementsMatch(t, scopes, tt.res.scopes)
		})
	}
}

func TestValidateAuthReqRedirectURI(t *testing.T) {
	type args struct {
		uri          string
		client       op.Client
		responseType oidc.ResponseType
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"empty fails",
			args{
				"",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"unregistered https fails",
			args{
				"https://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"unregistered http fails",
			args{
				"http://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow registered https web ok",
			args{
				"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow registered https native ok",
			args{
				"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow registered https user agent ok",
			args{
				"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow registered http confidential (web) ok",
			args{
				"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow registered http not confidential (native) fails",
			args{
				"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow registered http not confidential (user agent) fails",
			args{
				"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow registered http localhost native ok",
			args{
				"http://localhost:4200/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow registered http loopback v4 native ok",
			args{
				"http://127.0.0.1:4200/callback",
				mock.NewClientWithConfig(t, []string{"http://127.0.0.1/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow registered http loopback v6 native ok",
			args{
				"http://[::1]:4200/callback",
				mock.NewClientWithConfig(t, []string{"http://[::1]/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow unregistered http native fails",
			args{
				"http://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://locahost/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow unregistered custom native fails",
			args{
				"unregistered://callback",
				mock.NewClientWithConfig(t, []string{"registered://callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow unregistered loopback native fails",
			args{
				"http://[::1]:4200/unregistered",
				mock.NewClientWithConfig(t, []string{"http://[::1]:4200/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow registered custom not native (web) fails",
			args{
				"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow registered custom not native (user agent) fails",
			args{
				"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeCode,
			},
			true,
		},
		{
			"code flow registered custom native ok",
			args{
				"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow dev mode http ok",
			args{
				"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"implicit flow registered ok",
			args{
				"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeIDToken,
			},
			false,
		},
		{
			"implicit flow unregistered fails",
			args{
				"https://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeIDToken,
			},
			true,
		},
		{
			"implicit flow registered http localhost native ok",
			args{
				"http://localhost:9999/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost:9999/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeIDToken,
			},
			false,
		},
		{
			"implicit flow registered http localhost web fails",
			args{
				"http://localhost:9999/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost:9999/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeIDToken,
			},
			true,
		},
		{
			"implicit flow registered http localhost user agent fails",
			args{
				"http://localhost:9999/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost:9999/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeIDToken,
			},
			true,
		},
		{
			"implicit flow http non localhost fails",
			args{
				"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeIDToken,
			},
			true,
		},
		{
			"implicit flow custom fails",
			args{
				"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeIDToken,
			},
			false,
		},
		{
			"implicit flow dev mode http ok",
			args{
				"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeIDToken,
			},
			false,
		},
		{
			"code flow dev mode has redirect globs regular ok",
			args{
				"http://registered.com/callback",
				mock.NewHasRedirectGlobsWithConfig(t, []string{"http://registered.com/*"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow dev mode has redirect globs wildcard ok",
			args{
				"http://registered.com/callback",
				mock.NewHasRedirectGlobsWithConfig(t, []string{"http://registered.com/*"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow dev mode has redirect globs double star ok",
			args{
				"http://registered.com/callback",
				mock.NewHasRedirectGlobsWithConfig(t, []string{"http://**/*"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow dev mode has redirect globs double star ok",
			args{
				"http://registered.com/callback",
				mock.NewHasRedirectGlobsWithConfig(t, []string{"http://**/*"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow dev mode has redirect globs IPv6 ok",
			args{
				"http://[::1]:80/callback",
				mock.NewHasRedirectGlobsWithConfig(t, []string{"http://\\[::1\\]:80/*"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode,
			},
			false,
		},
		{
			"code flow dev mode has redirect globs bad pattern",
			args{
				"http://registered.com/callback",
				mock.NewHasRedirectGlobsWithConfig(t, []string{"http://**/\\"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := op.ValidateAuthReqRedirectURI(tt.args.client, tt.args.uri, tt.args.responseType); (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURI() error = %v, wantErr %v", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoopbackOrLocalhost(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"not parsable, false",
			args{url: string('\n')},
			false,
		},
		{
			"not http, false",
			args{url: "localhost/test"},
			false,
		},
		{
			"not http, false",
			args{url: "http://localhost.com/test"},
			false,
		},
		{
			"v4 no port ok",
			args{url: "http://127.0.0.1/test"},
			true,
		},
		{
			"v6 short no port ok",
			args{url: "http://[::1]/test"},
			true,
		},
		{
			"v6 long no port ok",
			args{url: "http://[0:0:0:0:0:0:0:1]/test"},
			true,
		},
		{
			"locahost no port ok",
			args{url: "http://localhost/test"},
			true,
		},
		{
			"v4 with port ok",
			args{url: "http://127.0.0.1:4200/test"},
			true,
		},
		{
			"v6 short with port ok",
			args{url: "http://[::1]:4200/test"},
			true,
		},
		{
			"v6 long with port ok",
			args{url: "http://[0:0:0:0:0:0:0:1]:4200/test"},
			true,
		},
		{
			"localhost with port ok",
			args{url: "http://localhost:4200/test"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := op.HTTPLoopbackOrLocalhost(tt.args.url); got != tt.want {
				t.Errorf("loopbackOrLocalhost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAuthReqResponseType(t *testing.T) {
	type args struct {
		responseType oidc.ResponseType
		client       op.Client
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"empty response type",
			args{
				"",
				mock.NewClientWithConfig(t, nil, op.ApplicationTypeNative, []oidc.ResponseType{oidc.ResponseTypeCode}, true),
			},
			true,
		},
		{
			"response type missing in client config",
			args{
				oidc.ResponseTypeIDToken,
				mock.NewClientWithConfig(t, nil, op.ApplicationTypeNative, []oidc.ResponseType{oidc.ResponseTypeCode}, true),
			},
			true,
		},
		{
			"valid response type",
			args{
				oidc.ResponseTypeCode,
				mock.NewClientWithConfig(t, nil, op.ApplicationTypeNative, []oidc.ResponseType{oidc.ResponseTypeCode}, true),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := op.ValidateAuthReqResponseType(tt.args.client, tt.args.responseType); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthReqScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRedirectToLogin(t *testing.T) {
	type args struct {
		authReqID string
		client    op.Client
		w         http.ResponseWriter
		r         *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"redirect ok",
			args{
				"id",
				mock.NewClientExpectAny(t, op.ApplicationTypeNative),
				httptest.NewRecorder(),
				httptest.NewRequest("GET", "/authorize", nil),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.RedirectToLogin(tt.args.authReqID, tt.args.client, tt.args.w, tt.args.r)
			rec := tt.args.w.(*httptest.ResponseRecorder)
			require.Equal(t, http.StatusFound, rec.Code)
			require.Equal(t, "/login?id=id", rec.Header().Get("location"))
		})
	}
}

func TestAuthResponseURL(t *testing.T) {
	type args struct {
		redirectURI  string
		responseType oidc.ResponseType
		responseMode oidc.ResponseMode
		response     any
		encoder      httphelper.Encoder
	}
	type res struct {
		url string
		err error
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"encoding error",
			args{
				"uri",
				oidc.ResponseTypeCode,
				"",
				map[string]any{"test": "test"},
				&mockEncoder{
					errors.New("error encoding"),
				},
			},
			res{
				"",
				oidc.ErrServerError(),
			},
		},
		{
			"response mode query",
			args{
				"uri",
				oidc.ResponseTypeIDToken,
				oidc.ResponseModeQuery,
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri?test=test",
				nil,
			},
		},
		{
			"response mode fragment",
			args{
				"uri",
				oidc.ResponseTypeCode,
				oidc.ResponseModeFragment,
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri#test=test",
				nil,
			},
		},
		{
			"response type code",
			args{
				"uri",
				oidc.ResponseTypeCode,
				"",
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri?test=test",
				nil,
			},
		},
		{
			"response type id token",
			args{
				"uri",
				oidc.ResponseTypeIDToken,
				"",
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri#test=test",
				nil,
			},
		},
		{
			"with query",
			args{
				"uri?param=value",
				oidc.ResponseTypeCode,
				"",
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri?param=value&test=test",
				nil,
			},
		},
		{
			"with query response type id token",
			args{
				"uri?param=value",
				oidc.ResponseTypeIDToken,
				"",
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri?param=value#test=test",
				nil,
			},
		},
		{
			"with existing query",
			args{
				"uri?test=value",
				oidc.ResponseTypeCode,
				"",
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri?test=value&test=test",
				nil,
			},
		},
		{
			"with existing query response type id token",
			args{
				"uri?test=value",
				oidc.ResponseTypeIDToken,
				"",
				map[string][]string{"test": {"test"}},
				&mockEncoder{},
			},
			res{
				"uri?test=value#test=test",
				nil,
			},
		},
		{
			"with existing query and multiple values",
			args{
				"uri?test=value",
				oidc.ResponseTypeCode,
				"",
				map[string][]string{"test": {"test", "test2"}},
				&mockEncoder{},
			},
			res{
				"uri?test=value&test=test&test=test2",
				nil,
			},
		},
		{
			"with existing query and multiple values response type id token",
			args{
				"uri?test=value",
				oidc.ResponseTypeIDToken,
				"",
				map[string][]string{"test": {"test", "test2"}},
				&mockEncoder{},
			},
			res{
				"uri?test=value#test=test&test=test2",
				nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.AuthResponseURL(tt.args.redirectURI, tt.args.responseType, tt.args.responseMode, tt.args.response, tt.args.encoder)
			if tt.res.err == nil && err != nil {
				t.Errorf("ValidateAuthRequest() unexpected error = %v", err)
			}
			if tt.res.err != nil && !errors.Is(err, tt.res.err) {
				t.Errorf("ValidateAuthRequest() unexpected error = %v, want = %v", err, tt.res.err)
			}
			if got != tt.res.url {
				t.Errorf("AuthResponseURL() got = %v, want %v", got, tt.res.url)
			}
		})
	}
}

type mockEncoder struct {
	err error
}

func (m *mockEncoder) Encode(src any, dst map[string][]string) error {
	if m.err != nil {
		return m.err
	}
	for s, strings := range src.(map[string][]string) {
		dst[s] = strings
	}
	return nil
}

// mockCrypto implements the op.Crypto interface
// and in always equals out. (It doesn't crypt anything).
// When returnErr != nil, that error is always returned instread.
type mockCrypto struct {
	returnErr error
}

func (c *mockCrypto) Encrypt(s string) (string, error) {
	if c.returnErr != nil {
		return "", c.returnErr
	}
	return s, nil
}

func (c *mockCrypto) Decrypt(s string) (string, error) {
	if c.returnErr != nil {
		return "", c.returnErr
	}
	return s, nil
}

func TestAuthResponseCode(t *testing.T) {
	type args struct {
		authReq    op.AuthRequest
		authorizer func(*testing.T) op.Authorizer
	}
	type res struct {
		wantCode               int
		wantLocationHeader     string
		wantCacheControlHeader string
		wantBody               string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			name: "create code error",
			args: args{
				authReq: &storage.AuthRequest{
					ID:            "id1",
					TransferState: "state1",
				},
				authorizer: func(t *testing.T) op.Authorizer {
					ctrl := gomock.NewController(t)
					storage := mock.NewMockStorage(ctrl)

					authorizer := mock.NewMockAuthorizer(ctrl)
					authorizer.EXPECT().Storage().Return(storage)
					authorizer.EXPECT().Crypto().Return(&mockCrypto{
						returnErr: io.ErrClosedPipe,
					})
					authorizer.EXPECT().Logger().Return(slog.Default())
					return authorizer
				},
			},
			res: res{
				wantCode: http.StatusBadRequest,
				wantBody: "io: read/write on closed pipe\n",
			},
		},
		{
			name: "success with state",
			args: args{
				authReq: &storage.AuthRequest{
					ID:            "id1",
					TransferState: "state1",
				},
				authorizer: func(t *testing.T) op.Authorizer {
					ctrl := gomock.NewController(t)
					storage := mock.NewMockStorage(ctrl)
					storage.EXPECT().SaveAuthCode(gomock.Any(), "id1", "id1")

					authorizer := mock.NewMockAuthorizer(ctrl)
					authorizer.EXPECT().Storage().Return(storage)
					authorizer.EXPECT().Crypto().Return(&mockCrypto{})
					authorizer.EXPECT().Encoder().Return(schema.NewEncoder())
					return authorizer
				},
			},
			res: res{
				wantCode:           http.StatusFound,
				wantLocationHeader: "/auth/callback/?code=id1&state=state1",
				wantBody:           "",
			},
		},
		{
			name: "success without state", // reproduce issue #415
			args: args{
				authReq: &storage.AuthRequest{
					ID:            "id1",
					TransferState: "",
				},
				authorizer: func(t *testing.T) op.Authorizer {
					ctrl := gomock.NewController(t)
					storage := mock.NewMockStorage(ctrl)
					storage.EXPECT().SaveAuthCode(gomock.Any(), "id1", "id1")

					authorizer := mock.NewMockAuthorizer(ctrl)
					authorizer.EXPECT().Storage().Return(storage)
					authorizer.EXPECT().Crypto().Return(&mockCrypto{})
					authorizer.EXPECT().Encoder().Return(schema.NewEncoder())
					return authorizer
				},
			},
			res: res{
				wantCode:           http.StatusFound,
				wantLocationHeader: "/auth/callback/?code=id1",
				wantBody:           "",
			},
		},
		{
			name: "success form_post",
			args: args{
				authReq: &storage.AuthRequest{
					ID:            "id1",
					CallbackURI:   "https://example.com/callback",
					TransferState: "state1",
					ResponseMode:  "form_post",
				},
				authorizer: func(t *testing.T) op.Authorizer {
					ctrl := gomock.NewController(t)
					storage := mock.NewMockStorage(ctrl)
					storage.EXPECT().SaveAuthCode(gomock.Any(), "id1", "id1")

					authorizer := mock.NewMockAuthorizer(ctrl)
					authorizer.EXPECT().Storage().Return(storage)
					authorizer.EXPECT().Crypto().Return(&mockCrypto{})
					authorizer.EXPECT().Encoder().Return(schema.NewEncoder())
					return authorizer
				},
			},
			res: res{
				wantCode:               http.StatusOK,
				wantCacheControlHeader: "no-store",
				wantBody:               "<!doctype html>\n<html>\n<head><meta charset=\"UTF-8\" /></head>\n<body onload=\"javascript:document.forms[0].submit()\">\n<form method=\"post\" action=\"https://example.com/callback\">\n<input type=\"hidden\" name=\"state\" value=\"state1\"/>\n<input type=\"hidden\" name=\"code\" value=\"id1\" />\n\n\n\n\n</form>\n</body>\n</html>",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/auth/callback/", nil)
			w := httptest.NewRecorder()
			op.AuthResponseCode(w, r, tt.args.authReq, tt.args.authorizer(t))
			resp := w.Result()
			defer resp.Body.Close()
			assert.Equal(t, tt.res.wantCode, resp.StatusCode)
			assert.Equal(t, tt.res.wantLocationHeader, resp.Header.Get("Location"))
			assert.Equal(t, tt.res.wantCacheControlHeader, resp.Header.Get("Cache-Control"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.res.wantBody, string(body))
		})
	}
}

func Test_parseAuthorizeCallbackRequest(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantId  string
		wantErr bool
	}{
		{
			name:    "parse error",
			url:     "/?id;=99",
			wantErr: true,
		},
		{
			name:    "missing id",
			url:     "/",
			wantErr: true,
		},
		{
			name:   "ok",
			url:    "/?id=99",
			wantId: "99",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			gotId, err := op.ParseAuthorizeCallbackRequest(r)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantId, gotId)
		})
	}
}

func TestValidateAuthReqIDTokenHint(t *testing.T) {
	token, _ := tu.ValidIDToken()
	tests := []struct {
		name        string
		idTokenHint string
		want        string
		wantErr     error
	}{
		{
			name: "empty",
		},
		{
			name:        "verify err",
			idTokenHint: "foo",
			wantErr:     oidc.ErrLoginRequired(),
		},
		{
			name:        "ok",
			idTokenHint: token,
			want:        tu.ValidSubject,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.ValidateAuthReqIDTokenHint(context.Background(), tt.idTokenHint, op.NewIDTokenHintVerifier(tu.ValidIssuer, tu.KeySet{}))
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

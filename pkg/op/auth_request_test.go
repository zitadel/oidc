package op_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/gorilla/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	httphelper "github.com/caos/oidc/pkg/http"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
	"github.com/caos/oidc/pkg/op/mock"
)

//
//TOOD: tests will be implemented in branch for service accounts
//func TestAuthorize(t *testing.T) {
//	// testCallback := func(t *testing.T, clienID string) callbackHandler {
//	// 	return func(authReq *oidc.AuthRequest, client oidc.Client, w http.ResponseWriter, r *http.Request) {
//	// 		// require.Equal(t, clientID, client.)
//	// 	}
//	// }
//	// testErr := func(t *testing.T, expected error) errorHandler {
//	// 	return func(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error) {
//	// 		require.Equal(t, expected, err)
//	// 	}
//	// }
//	type args struct {
//		w          http.ResponseWriter
//		r          *http.Request
//		authorizer op.Authorizer
//	}
//	tests := []struct {
//		name string
//		args args
//	}{
//		{
//			"parsing fails",
//			args{
//				httptest.NewRecorder(),
//				&http.Request{Method: "POST", Body: nil},
//				mock.NewAuthorizerExpectValid(t, true),
//				// testCallback(t, ""),
//				// testErr(t, ErrInvalidRequest("cannot parse form")),
//			},
//		},
//		{
//			"decoding fails",
//			args{
//				httptest.NewRecorder(),
//				func() *http.Request {
//					r := httptest.NewRequest("POST", "/authorize", strings.NewReader("client_id=foo"))
//					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
//					return r
//				}(),
//				mock.NewAuthorizerExpectValid(t, true),
//				// testCallback(t, ""),
//				// testErr(t, ErrInvalidRequest("cannot parse auth request")),
//			},
//		},
//		// {"decoding fails", args{httptest.NewRecorder(), &http.Request{}, mock.NewAuthorizerExpectValid(t), nil, testErr(t, nil)}},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			op.Authorize(tt.args.w, tt.args.r, tt.args.authorizer)
//		})
//	}
//}

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

//TODO: extend cases
func TestValidateAuthRequest(t *testing.T) {
	type args struct {
		authRequest *oidc.AuthRequest
		storage     op.Storage
		verifier    op.IDTokenHintVerifier
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		//TODO:
		// {
		// 	"oauth2 spec"
		// }
		{
			"scope missing fails",
			args{&oidc.AuthRequest{}, mock.NewMockStorageExpectValidClientID(t), nil},
			oidc.ErrInvalidRequest(),
		},
		{
			"scope openid missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"profile"}}, mock.NewMockStorageExpectValidClientID(t), nil},
			oidc.ErrInvalidScope(),
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

//TODO: implement
func TestValidateAuthReqPrompt(t *testing.T) {}

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
			"scope openid missing fails",
			args{
				mock.NewClientExpectAny(t, op.ApplicationTypeWeb),
				[]string{"email"},
			},
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
			args{"",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"unregistered https fails",
			args{"https://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"unregistered http fails",
			args{"http://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow registered https web ok",
			args{"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow registered https native ok",
			args{"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow registered https user agent ok",
			args{"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow registered http confidential (web) ok",
			args{"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow registered http not confidential (native) fails",
			args{"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow registered http not confidential (user agent) fails",
			args{"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow registered http localhost native ok",
			args{"http://localhost:4200/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow registered http loopback v4 native ok",
			args{"http://127.0.0.1:4200/callback",
				mock.NewClientWithConfig(t, []string{"http://127.0.0.1/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow registered http loopback v6 native ok",
			args{"http://[::1]:4200/callback",
				mock.NewClientWithConfig(t, []string{"http://[::1]/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow unregistered http native fails",
			args{"http://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://locahost/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow unregistered custom native fails",
			args{"unregistered://callback",
				mock.NewClientWithConfig(t, []string{"registered://callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow unregistered loopback native fails",
			args{"http://[::1]:4200/unregistered",
				mock.NewClientWithConfig(t, []string{"http://[::1]:4200/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow registered custom not native (web) fails",
			args{"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow registered custom not native (user agent) fails",
			args{"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeCode},
			true,
		},
		{
			"code flow registered custom native ok",
			args{"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"code flow dev mode http ok",
			args{"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeCode},
			false,
		},
		{
			"implicit flow registered ok",
			args{"https://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeIDToken},
			false,
		},
		{
			"implicit flow unregistered fails",
			args{"https://unregistered.com/callback",
				mock.NewClientWithConfig(t, []string{"https://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeIDToken},
			true,
		},
		{
			"implicit flow registered http localhost native ok",
			args{"http://localhost:9999/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost:9999/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeIDToken},
			false,
		},
		{
			"implicit flow registered http localhost web fails",
			args{"http://localhost:9999/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost:9999/callback"}, op.ApplicationTypeWeb, nil, false),
				oidc.ResponseTypeIDToken},
			true,
		},
		{
			"implicit flow registered http localhost user agent fails",
			args{"http://localhost:9999/callback",
				mock.NewClientWithConfig(t, []string{"http://localhost:9999/callback"}, op.ApplicationTypeUserAgent, nil, false),
				oidc.ResponseTypeIDToken},
			true,
		},
		{
			"implicit flow http non localhost fails",
			args{"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeIDToken},
			true,
		},
		{
			"implicit flow custom fails",
			args{"custom://callback",
				mock.NewClientWithConfig(t, []string{"custom://callback"}, op.ApplicationTypeNative, nil, false),
				oidc.ResponseTypeIDToken},
			false,
		},
		{
			"implicit flow dev mode http ok",
			args{"http://registered.com/callback",
				mock.NewClientWithConfig(t, []string{"http://registered.com/callback"}, op.ApplicationTypeUserAgent, nil, true),
				oidc.ResponseTypeIDToken},
			false,
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

//TODO: test not parsable url
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
			args{"",
				mock.NewClientWithConfig(t, nil, op.ApplicationTypeNative, []oidc.ResponseType{oidc.ResponseTypeCode}, true)},
			true,
		},
		{
			"response type missing in client config",
			args{oidc.ResponseTypeIDToken,
				mock.NewClientWithConfig(t, nil, op.ApplicationTypeNative, []oidc.ResponseType{oidc.ResponseTypeCode}, true)},
			true,
		},
		{
			"valid response type",
			args{oidc.ResponseTypeCode,
				mock.NewClientWithConfig(t, nil, op.ApplicationTypeNative, []oidc.ResponseType{oidc.ResponseTypeCode}, true)},
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

//TODO: implement
func TestValidateAuthReqIDTokenHint(t *testing.T) {}

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

//TODO: implement
func TestAuthorizeCallback(t *testing.T) {
	type args struct {
		w          http.ResponseWriter
		r          *http.Request
		authorizer op.Authorizer
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.AuthorizeCallback(tt.args.w, tt.args.r, tt.args.authorizer)
		})
	}
}

//TODO: implement
func TestAuthResponse(t *testing.T) {
	type args struct {
		authReq    op.AuthRequest
		authorizer op.Authorizer
		w          http.ResponseWriter
		r          *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.AuthResponse(tt.args.authReq, tt.args.authorizer, tt.args.w, tt.args.r)
		})
	}
}

//TODO: implement
func TestAuthResponseCode(t *testing.T) {}

//TODO: implement
func TestAuthResponseToken(t *testing.T) {}

//TODO: implement
func TestCreateAuthRequestCode(t *testing.T) {}

//TODO: implement
func TestBuildAuthRequestCode(t *testing.T) {}

package op_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
	"github.com/caos/oidc/pkg/op/mock"
)

func TestAuthorize(t *testing.T) {
	// testCallback := func(t *testing.T, clienID string) callbackHandler {
	// 	return func(authReq *oidc.AuthRequest, client oidc.Client, w http.ResponseWriter, r *http.Request) {
	// 		// require.Equal(t, clientID, client.)
	// 	}
	// }
	// testErr := func(t *testing.T, expected error) errorHandler {
	// 	return func(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error) {
	// 		require.Equal(t, expected, err)
	// 	}
	// }
	type args struct {
		w          http.ResponseWriter
		r          *http.Request
		authorizer op.Authorizer
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"parsing fails",
			args{
				httptest.NewRecorder(),
				&http.Request{Method: "POST", Body: nil},
				mock.NewAuthorizerExpectValid(t, true),
				// testCallback(t, ""),
				// testErr(t, ErrInvalidRequest("cannot parse form")),
			},
		},
		{
			"decoding fails",
			args{
				httptest.NewRecorder(),
				func() *http.Request {
					r := httptest.NewRequest("POST", "/authorize", strings.NewReader("client_id=foo"))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					return r
				}(),
				mock.NewAuthorizerExpectValid(t, true),
				// testCallback(t, ""),
				// testErr(t, ErrInvalidRequest("cannot parse auth request")),
			},
		},
		// {"decoding fails", args{httptest.NewRecorder(), &http.Request{}, mock.NewAuthorizerExpectValid(t), nil, testErr(t, nil)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.Authorize(tt.args.w, tt.args.r, tt.args.authorizer)
		})
	}
}

func TestValidateAuthRequest(t *testing.T) {
	type args struct {
		authRequest *oidc.AuthRequest
		storage     op.Storage
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		//TODO:
		// {
		// 	"oauth2 spec"
		// }
		{
			"scope missing fails",
			args{&oidc.AuthRequest{}, nil},
			true,
		},
		{
			"scope openid missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"profile"}}, nil},
			true,
		},
		{
			"response_type missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"openid"}}, nil},
			true,
		},
		{
			"client_id missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"openid"}, ResponseType: oidc.ResponseTypeCode}, nil},
			true,
		},
		{
			"redirect_uri missing fails",
			args{&oidc.AuthRequest{Scopes: []string{"openid"}, ResponseType: oidc.ResponseTypeCode, ClientID: "client_id"}, nil},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := op.ValidateAuthRequest(nil, tt.args.authRequest, tt.args.storage); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAuthReqScopes(t *testing.T) {
	type args struct {
		scopes []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"scopes missing fails", args{}, true,
		},
		{
			"scope openid missing fails", args{[]string{"email"}}, true,
		},
		{
			"scope ok", args{[]string{"openid"}}, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := op.ValidateAuthReqScopes(tt.args.scopes); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthReqScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAuthReqRedirectURI(t *testing.T) {
	type args struct {
		uri          string
		clientID     string
		responseType oidc.ResponseType
		storage      op.OPStorage
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"empty fails",
			args{"", "", oidc.ResponseTypeCode, nil},
			true,
		},
		{
			"unregistered fails",
			args{"https://unregistered.com/callback", "web_client", oidc.ResponseTypeCode, mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
		{
			"storage error fails",
			args{"https://registered.com/callback", "non_client", oidc.ResponseTypeIDToken, mock.NewMockStorageExpectInvalidClientID(t)},
			true,
		},
		{
			"code flow registered http not confidential fails",
			args{"http://registered.com/callback", "useragent_client", oidc.ResponseTypeCode, mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
		{
			"code flow registered http confidential ok",
			args{"http://registered.com/callback", "web_client", oidc.ResponseTypeCode, mock.NewMockStorageExpectValidClientID(t)},
			false,
		},
		{
			"code flow registered custom not native fails",
			args{"custom://callback", "useragent_client", oidc.ResponseTypeCode, mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
		{
			"code flow registered custom native ok",
			args{"http://registered.com/callback", "native_client", oidc.ResponseTypeCode, mock.NewMockStorageExpectValidClientID(t)},
			false,
		},
		{
			"implicit flow registered ok",
			args{"https://registered.com/callback", "useragent_client", oidc.ResponseTypeIDToken, mock.NewMockStorageExpectValidClientID(t)},
			false,
		},
		{
			"implicit flow registered http localhost native ok",
			args{"http://localhost:9999/callback", "native_client", oidc.ResponseTypeIDToken, mock.NewMockStorageExpectValidClientID(t)},
			false,
		},
		{
			"implicit flow registered http localhost user agent fails",
			args{"http://localhost:9999/callback", "useragent_client", oidc.ResponseTypeIDToken, mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
		{
			"implicit flow http non localhost fails",
			args{"http://registered.com/callback", "native_client", oidc.ResponseTypeIDToken, mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
		{
			"implicit flow custom fails",
			args{"custom://callback", "native_client", oidc.ResponseTypeIDToken, mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := op.ValidateAuthReqRedirectURI(nil, tt.args.uri, tt.args.clientID, tt.args.responseType, tt.args.storage); (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURI() error = %v, wantErr %v", err.Error(), tt.wantErr)
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

package op

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
	"github.com/caos/oidc/pkg/op/mock"
)

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
			if err := ValidateAuthRequest(tt.args.authRequest, tt.args.storage); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAuthReqRedirectURI(t *testing.T) {
	type args struct {
		uri          string
		clientID     string
		responseType oidc.ResponseType
		storage      op.Storage
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
			if err := ValidateAuthReqRedirectURI(tt.args.uri, tt.args.clientID, tt.args.responseType, tt.args.storage); (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURI() error = %v, wantErr %v", err.Error(), tt.wantErr)
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
			if err := ValidateAuthReqScopes(tt.args.scopes); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthReqScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	type args struct {
		w       http.ResponseWriter
		r       *http.Request
		storage Storage
		decoder *schema.Decoder
	}
	tests := []struct {
		name string
		args args
	}{
		{"parsing fails", args{httptest.NewRecorder(), &http.Request{Method: "POST", Body: nil}, nil, nil}},
		{"decoding fails", args{httptest.NewRecorder(), &http.Request{}, nil, schema.NewDecoder()}},
		{"decoding fails", args{httptest.NewRecorder(), &http.Request{}, nil, schema.NewDecoder()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Authorize(tt.args.w, tt.args.r, tt.args.storage, tt.args.decoder)
		})
	}
}

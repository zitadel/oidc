package op

import (
	"testing"

	"github.com/caos/oidc/pkg/op"
	"github.com/caos/oidc/pkg/op/mock"

	"github.com/caos/oidc/pkg/oidc"
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

func TestValidateRedirectURI(t *testing.T) {
	type args struct {
		uri      string
		clientID string
		storage  op.Storage
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"empty fails",
			args{"", "", nil},
			true,
		},
		{
			"unregistered fails",
			args{"https://unregistered.com/callback", "client_id", mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
		{
			"http not allowed fails",
			args{"http://registered.com/callback", "client_id", mock.NewMockStorageExpectValidClientID(t)},
			true,
		},
		{
			"registered https ok",
			args{"https://registered.com/callback", "client_id", mock.NewMockStorageExpectValidClientID(t)},
			false,
		},
		{
			"registered http allowed ok",
			args{"http://localhost:9999/callback", "client_id", mock.NewMockStorageExpectValidClientID(t)},
			false,
		},
		{
			"registered scheme ok",
			args{"custom://callback", "client_id", mock.NewMockStorageExpectValidClientID(t)},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAuthReqRedirectURI(tt.args.uri, tt.args.clientID, tt.args.storage); (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

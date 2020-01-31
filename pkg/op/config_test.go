package op

import "testing"

import "os"

func TestValidateIssuer(t *testing.T) {
	type args struct {
		issuer string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"missing issuer fails",
			args{""},
			true,
		},
		{
			"invalid url for issuer fails",
			args{":issuer"},
			true,
		},
		{
			"invalid url for issuer fails",
			args{":issuer"},
			true,
		},
		{
			"host for issuer missing fails",
			args{"https:///issuer"},
			true,
		},
		{
			"host for not https fails",
			args{"http://issuer.com"},
			true,
		},
		{
			"host with fragment fails",
			args{"https://issuer.com/#issuer"},
			true,
		},
		{
			"host with query fails",
			args{"https://issuer.com?issuer=me"},
			true,
		},
		{
			"host with https ok",
			args{"https://issuer.com"},
			false,
		},
		{
			"localhost with http ok",
			args{"http://localhost:9999"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIssuer(tt.args.issuer); (err != nil) != tt.wantErr {
				t.Errorf("ValidateIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIssuerDevLocalAllowed(t *testing.T) {
	type args struct {
		issuer string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"localhost with http ok",
			args{"http://localhost:9999"},
			false,
		},
	}
	os.Setenv("CAOS_OIDC_DEV", "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIssuer(tt.args.issuer); (err != nil) != tt.wantErr {
				t.Errorf("ValidateIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

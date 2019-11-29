package op_test

import (
	"testing"

	"github.com/caos/oidc/pkg/op"
)

func TestEndpoint_Relative(t *testing.T) {
	tests := []struct {
		name string
		e    op.Endpoint
		want string
	}{
		{
			"without starting /",
			op.Endpoint("test"),
			"/test",
		},
		{
			"with starting /",
			op.Endpoint("/test"),
			"/test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Relative(); got != tt.want {
				t.Errorf("Endpoint.Relative() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpoint_Absolute(t *testing.T) {
	type args struct {
		host string
	}
	tests := []struct {
		name string
		e    op.Endpoint
		args args
		want string
	}{
		{
			"no /",
			op.Endpoint("test"),
			args{"https://host"},
			"https://host/test",
		},
		{
			"endpoint without /",
			op.Endpoint("test"),
			args{"https://host/"},
			"https://host/test",
		},
		{
			"host without /",
			op.Endpoint("/test"),
			args{"https://host"},
			"https://host/test",
		},
		{
			"both /",
			op.Endpoint("/test"),
			args{"https://host/"},
			"https://host/test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Absolute(tt.args.host); got != tt.want {
				t.Errorf("Endpoint.Absolute() = %v, want %v", got, tt.want)
			}
		})
	}
}

//TODO: impl test
func TestEndpoint_Validate(t *testing.T) {
	tests := []struct {
		name    string
		e       op.Endpoint
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.e.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Endpoint.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

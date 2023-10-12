package op_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestEndpoint_Path(t *testing.T) {
	tests := []struct {
		name string
		e    *op.Endpoint
		want string
	}{
		{
			"without starting /",
			op.NewEndpoint("test"),
			"/test",
		},
		{
			"with starting /",
			op.NewEndpoint("/test"),
			"/test",
		},
		{
			"with url",
			op.NewEndpointWithURL("/test", "http://test.com/test"),
			"/test",
		},
		{
			"nil",
			nil,
			"",
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
		e    *op.Endpoint
		args args
		want string
	}{
		{
			"no /",
			op.NewEndpoint("test"),
			args{"https://host"},
			"https://host/test",
		},
		{
			"endpoint without /",
			op.NewEndpoint("test"),
			args{"https://host/"},
			"https://host/test",
		},
		{
			"host without /",
			op.NewEndpoint("/test"),
			args{"https://host"},
			"https://host/test",
		},
		{
			"both /",
			op.NewEndpoint("/test"),
			args{"https://host/"},
			"https://host/test",
		},
		{
			"with url",
			op.NewEndpointWithURL("test", "https://test.com/test"),
			args{"https://host"},
			"https://test.com/test",
		},
		{
			"nil",
			nil,
			args{"https://host"},
			"",
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

// TODO: impl test
func TestEndpoint_Validate(t *testing.T) {
	tests := []struct {
		name    string
		e       *op.Endpoint
		wantErr error
	}{
		{
			"nil",
			nil,
			op.ErrNilEndpoint,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.e.Validate()
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

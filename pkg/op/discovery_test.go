package op_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
)

func TestDiscover(t *testing.T) {
	type args struct {
		w      http.ResponseWriter
		config *oidc.DiscoveryConfiguration
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"OK",
			args{
				httptest.NewRecorder(),
				&oidc.DiscoveryConfiguration{Issuer: "https://issuer.com"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.Discover(tt.args.w, tt.args.config)
			rec := tt.args.w.(*httptest.ResponseRecorder)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, `{"issuer":"https://issuer.com"}`, rec.Body.String())
		})
	}
}

func TestCreateDiscoveryConfig(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want *oidc.DiscoveryConfiguration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.CreateDiscoveryConfig(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateDiscoveryConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

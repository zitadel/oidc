package op

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/caos/oidc/pkg/oidc"
)

func TestDefaultOP_HandleDiscovery(t *testing.T) {
	type fields struct {
		config          *Config
		endpoints       *endpoints
		discoveryConfig *oidc.DiscoveryConfiguration
		storage         Storage
		http            *http.Server
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		want     string
		wantCode int
	}{
		{"OK", fields{config: nil, endpoints: nil, discoveryConfig: &oidc.DiscoveryConfiguration{Issuer: "https://issuer.com"}}, args{httptest.NewRecorder(), nil}, `{"issuer":"https://issuer.com"}`, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &DefaultOP{
				config:          tt.fields.config,
				endpoints:       tt.fields.endpoints,
				discoveryConfig: tt.fields.discoveryConfig,
				storage:         tt.fields.storage,
				http:            tt.fields.http,
			}
			p.HandleDiscovery(tt.args.w, tt.args.r)
			rec := tt.args.w.(*httptest.ResponseRecorder)
			require.Equal(t, tt.want, rec.Body.String())
			require.Equal(t, tt.wantCode, rec.Code)
		})
	}
}

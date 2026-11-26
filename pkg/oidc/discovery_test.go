package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryConfiguration_AuthorizationResponseIssParameterSupported(t *testing.T) {
	tests := []struct {
		name      string
		supported bool
		wantKey   bool
	}{
		{name: "supported", supported: true, wantKey: true},
		{name: "not supported", supported: false, wantKey: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(&DiscoveryConfiguration{
				Issuer: "https://op.example.com/",
				AuthorizationResponseIssParameterSupported: tt.supported,
			})
			require.NoError(t, err)
			var fields map[string]any
			require.NoError(t, json.Unmarshal(got, &fields))
			value, ok := fields["authorization_response_iss_parameter_supported"]
			assert.Equal(t, tt.wantKey, ok)
			if tt.wantKey {
				assert.Equal(t, true, value)
			}
		})
	}
}

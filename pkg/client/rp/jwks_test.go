package rp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonWebKeySet_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		wantKeyLen int
		wantErr    bool
		errPrefix  string
	}{
		{
			name:       "valid key set",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "empty key set",
			jsonData:   `{"keys":[]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "unknown key type",
			jsonData:   `{"keys":[{"kty":"UNKNOWN","use":"sig","kid":"key1"}]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "mixed valid and unknown key types",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"},{"kty":"UNKNOWN","use":"sig","kid":"key2"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "invalid json",
			jsonData:   `{"keys":[{]`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshall key set: ",
		},
		{
			name:       "other error during key unmarshal",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256"}]}`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshal key 0 from set: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keySet jsonWebKeySet
			err := keySet.UnmarshalJSON([]byte(tt.jsonData))

			if tt.wantErr {
				assert.Error(t, err)
				assert.NotContains(t, err.Error(), joseUnknownKeyTypeErrMsg)
				assert.True(t, strings.HasPrefix(err.Error(), tt.errPrefix))

			} else {
				assert.NoError(t, err)
				assert.Len(t, keySet.Keys, tt.wantKeyLen)
			}
		})
	}
}

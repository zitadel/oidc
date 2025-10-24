package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/datasapiens/oidc/v3/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	type wantFields struct {
		UILocalesSupported bool
	}

	type args struct {
		issuer       string
		wellKnownUrl []string
	}
	tests := []struct {
		name       string
		args       args
		wantFields *wantFields
		wantErr    error
	}{
		{
			name: "spotify", // https://github.com/datasapiens/oidc/issues/406
			args: args{
				issuer: "https://accounts.spotify.com",
			},
			wantFields: &wantFields{
				UILocalesSupported: true,
			},
			wantErr: nil,
		},
		{
			name: "discovery failed",
			args: args{
				issuer: "https://example.com",
			},
			wantErr: oidc.ErrDiscoveryFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Discover(context.Background(), []string{tt.args.issuer}, http.DefaultClient, tt.args.wellKnownUrl...)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantFields == nil {
				return
			}
			assert.Equal(t, tt.args.issuer, got.Issuer)
			if tt.wantFields.UILocalesSupported {
				assert.NotEmpty(t, got.UILocalesSupported)
			}
		})
	}
}

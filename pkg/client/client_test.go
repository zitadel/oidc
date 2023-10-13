package client

import (
	"context"
	"net/http"
	"testing"

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
		wantErr    bool
	}{
		{
			name: "spotify", // https://github.com/zitadel/oidc/issues/406
			args: args{
				issuer: "https://accounts.spotify.com",
			},
			wantFields: &wantFields{
				UILocalesSupported: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Discover(context.Background(), tt.args.issuer, http.DefaultClient, tt.args.wellKnownUrl...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
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

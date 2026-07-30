package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v4/pkg/oidc"
)

type testTokenEndpointCaller struct {
	endpoint string
	client   *http.Client
}

func (c testTokenEndpointCaller) TokenEndpoint() string    { return c.endpoint }
func (c testTokenEndpointCaller) HttpClient() *http.Client { return c.client }

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
			name: "spotify", // https://github.com/zitadel/oidc/issues/406
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
			got, err := Discover(context.Background(), tt.args.issuer, http.DefaultClient, tt.args.wellKnownUrl...)
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

func TestCallTokenEndpointExpiry(t *testing.T) {
	for _, expiresIn := range []int64{1, 10, 3600, 86401} {
		t.Run(fmt.Sprintf("%d_seconds", expiresIn), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w,
					`{"access_token":"token","token_type":"Bearer","expires_in":%d}`,
					expiresIn,
				)
			}))
			defer server.Close()

			caller := testTokenEndpointCaller{
				endpoint: server.URL,
				client:   server.Client(),
			}

			before := time.Now().UTC().Unix()
			token, err := CallTokenEndpoint(context.Background(), struct{}{}, caller)
			require.NoError(t, err)
			after := time.Now().UTC().Unix()
			tokenExp := token.Expiry.Unix()

			// To prevent test failures where a second ticks just after we measure time.Now
			// we check (before+expiresIn) <= tokenExp <= (after+expiresIn)
			require.GreaterOrEqual(t, tokenExp, before+expiresIn)
			require.LessOrEqual(t, tokenExp, after+expiresIn)
		})
	}
}

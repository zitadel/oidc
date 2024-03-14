package rs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestNewResourceServer(t *testing.T) {
	type args struct {
		issuer     string
		authorizer func() (any, error)
		options    []Option
	}
	type wantFields struct {
		issuer        string
		tokenURL      string
		introspectURL string
		authFn        func() (any, error)
	}
	tests := []struct {
		name       string
		args       args
		wantFields *wantFields
		wantErr    bool
	}{
		{
			name: "spotify-full-discovery",
			args: args{
				issuer:     "https://accounts.spotify.com",
				authorizer: nil,
				options:    []Option{},
			},
			wantFields: &wantFields{
				issuer:        "https://accounts.spotify.com",
				tokenURL:      "https://accounts.spotify.com/api/token",
				introspectURL: "",
				authFn:        nil,
			},
			wantErr: false,
		},
		{
			name: "spotify-with-static-tokenurl",
			args: args{
				issuer:     "https://accounts.spotify.com",
				authorizer: nil,
				options: []Option{
					WithStaticEndpoints(
						"https://some.host/token-url",
						"",
					),
				},
			},
			wantFields: &wantFields{
				issuer:        "https://accounts.spotify.com",
				tokenURL:      "https://some.host/token-url",
				introspectURL: "",
				authFn:        nil,
			},
			wantErr: false,
		},
		{
			name: "spotify-with-static-introspecturl",
			args: args{
				issuer:     "https://accounts.spotify.com",
				authorizer: nil,
				options: []Option{
					WithStaticEndpoints(
						"",
						"https://some.host/instrospect-url",
					),
				},
			},
			wantFields: &wantFields{
				issuer:        "https://accounts.spotify.com",
				tokenURL:      "https://accounts.spotify.com/api/token",
				introspectURL: "https://some.host/instrospect-url",
				authFn:        nil,
			},
			wantErr: false,
		},
		{
			name: "spotify-with-all-static-endpoints",
			args: args{
				issuer:     "https://accounts.spotify.com",
				authorizer: nil,
				options: []Option{
					WithStaticEndpoints(
						"https://some.host/token-url",
						"https://some.host/instrospect-url",
					),
				},
			},
			wantFields: &wantFields{
				issuer:        "https://accounts.spotify.com",
				tokenURL:      "https://some.host/token-url",
				introspectURL: "https://some.host/instrospect-url",
				authFn:        nil,
			},
			wantErr: false,
		},
		{
			name: "bad-discovery",
			args: args{
				issuer:     "https://127.0.0.1:65535",
				authorizer: nil,
				options:    []Option{},
			},
			wantFields: nil,
			wantErr:    true,
		},
		{
			name: "bad-discovery-with-static-tokenurl",
			args: args{
				issuer:     "https://127.0.0.1:65535",
				authorizer: nil,
				options: []Option{
					WithStaticEndpoints(
						"https://some.host/token-url",
						"",
					),
				},
			},
			wantFields: nil,
			wantErr:    true,
		},
		{
			name: "bad-discovery-with-static-introspecturl",
			args: args{
				issuer:     "https://127.0.0.1:65535",
				authorizer: nil,
				options: []Option{
					WithStaticEndpoints(
						"",
						"https://some.host/instrospect-url",
					),
				},
			},
			wantFields: nil,
			wantErr:    true,
		},
		{
			name: "bad-discovery-with-all-static-endpoints",
			args: args{
				issuer:     "https://127.0.0.1:65535",
				authorizer: nil,
				options: []Option{
					WithStaticEndpoints(
						"https://some.host/token-url",
						"https://some.host/instrospect-url",
					),
				},
			},
			wantFields: &wantFields{
				issuer:        "https://127.0.0.1:65535",
				tokenURL:      "https://some.host/token-url",
				introspectURL: "https://some.host/instrospect-url",
				authFn:        nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newResourceServer(context.Background(), tt.args.issuer, tt.args.authorizer, tt.args.options...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantFields == nil {
				return
			}
			assert.Equal(t, tt.wantFields.issuer, got.issuer)
			assert.Equal(t, tt.wantFields.tokenURL, got.tokenURL)
			assert.Equal(t, tt.wantFields.introspectURL, got.introspectURL)
		})
	}
}

func TestIntrospect(t *testing.T) {
	type args struct {
		ctx   context.Context
		rp    ResourceServer
		token string
	}
	rp, err := newResourceServer(
		context.Background(),
		"https://accounts.spotify.com",
		nil,
	)
	require.NoError(t, err)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "missing-introspect-url",
			args: args{
				ctx:   context.Background(),
				rp:    rp,
				token: "my-token",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Introspect[*oidc.IntrospectionResponse](tt.args.ctx, tt.args.rp, tt.args.token)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

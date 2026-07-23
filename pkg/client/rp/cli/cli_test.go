package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCallbackServerConfig(t *testing.T) {
	tests := []struct {
		name         string
		redirectURI  string
		callbackPath string
		port         string
		wantListen   string
		wantLoginURL string
		wantErr      bool
	}{
		{
			name:         "IPv4 loopback",
			redirectURI:  "http://127.0.0.1:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantListen:   "127.0.0.1:3000",
			wantLoginURL: "http://127.0.0.1:3000/login",
		},
		{
			name:         "IPv6 loopback",
			redirectURI:  "http://[::1]:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantListen:   "[::1]:3000",
			wantLoginURL: "http://[::1]:3000/login",
		},
		{
			name:         "localhost compatibility",
			redirectURI:  "http://localhost:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantListen:   ":3000",
			wantLoginURL: "http://localhost:3000/login",
		},
		{
			name:         "missing port",
			redirectURI:  "http://127.0.0.1/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "port mismatch",
			redirectURI:  "http://127.0.0.1:3001/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "HTTPS",
			redirectURI:  "https://127.0.0.1:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "remote host",
			redirectURI:  "http://example.com:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "localhost lookalike",
			redirectURI:  "http://localhost.attacker.com:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "IPv4 lookalike",
			redirectURI:  "http://127.0.0.1.attacker.com:3000/callback",
			callbackPath: "/callback",
			port:         "3000",
			wantErr:      true,
		},
		{
			name:         "callback path mismatch",
			redirectURI:  "http://127.0.0.1:3000/callback",
			callbackPath: "/other",
			port:         "3000",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listenAddress, loginURL, err := callbackServerConfig(tt.redirectURI, tt.callbackPath, tt.port)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantListen, listenAddress)
			assert.Equal(t, tt.wantLoginURL, loginURL)
		})
	}
}

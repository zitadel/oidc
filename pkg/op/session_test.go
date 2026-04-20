package op_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
)

func TestValidateEndSessionPostLogoutRedirectURI(t *testing.T) {
	tests := []struct {
		name                  string
		registered            []string
		registeredGlobs       []string
		applicationType       op.ApplicationType
		postLogoutRedirectURI string
		useGlobsClient        bool
		wantErr               bool
	}{
		{
			name:                  "exact match (web)",
			registered:            []string{"https://logged-out"},
			applicationType:       op.ApplicationTypeWeb,
			postLogoutRedirectURI: "https://logged-out",
			wantErr:               false,
		},
		{
			name:                  "no match",
			registered:            []string{"https://logged-out"},
			applicationType:       op.ApplicationTypeWeb,
			postLogoutRedirectURI: "https://other",
			wantErr:               true,
		},
		{
			name:                  "native loopback v4 dynamic port ok",
			registered:            []string{"http://127.0.0.1/callback"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:54321/callback",
			wantErr:               false,
		},
		{
			name:                  "native loopback v6 dynamic port ok",
			registered:            []string{"http://[::1]/callback"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://[::1]:54321/callback",
			wantErr:               false,
		},
		{
			name:                  "native localhost dynamic port ok",
			registered:            []string{"http://localhost/callback"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://localhost:54321/callback",
			wantErr:               false,
		},
		{
			name:                  "native https loopback v4 dynamic port ok",
			registered:            []string{"https://127.0.0.1/callback"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "https://127.0.0.1:54321/callback",
			wantErr:               false,
		},
		{
			name:                  "native loopback wrong path fails",
			registered:            []string{"http://127.0.0.1/callback"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:54321/other",
			wantErr:               true,
		},
		{
			name:                  "native loopback exact (no port) ok",
			registered:            []string{"http://127.0.0.1/callback"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1/callback",
			wantErr:               false,
		},
		{
			name:                  "web loopback dynamic port fails",
			registered:            []string{"http://127.0.0.1/callback"},
			applicationType:       op.ApplicationTypeWeb,
			postLogoutRedirectURI: "http://127.0.0.1:54321/callback",
			wantErr:               true,
		},
		{
			name:                  "user-agent loopback dynamic port fails",
			registered:            []string{"http://127.0.0.1/callback"},
			applicationType:       op.ApplicationTypeUserAgent,
			postLogoutRedirectURI: "http://127.0.0.1:54321/callback",
			wantErr:               true,
		},
		{
			name:                  "native non-loopback exact still ok",
			registered:            []string{"https://example.com/lo"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "https://example.com/lo",
			wantErr:               false,
		},
		{
			name:                  "native non-loopback dynamic port fails",
			registered:            []string{"https://example.com/lo"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "https://example.com:8443/lo",
			wantErr:               true,
		},
		{
			// Matches the existing auth-side behavior: equalURI compares only
			// path + raw query, so any registered loopback host is interchangeable
			// with any incoming loopback host as long as the path matches.
			name:                  "native cross-loopback host ok (v4 registered, v6 request)",
			registered:            []string{"http://127.0.0.1/callback"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://[::1]:54321/callback",
			wantErr:               false,
		},
		{
			name:                  "glob match (HasRedirectGlobs)",
			registered:            []string{"https://logged-out"},
			registeredGlobs:       []string{"https://*.example.com"},
			applicationType:       op.ApplicationTypeWeb,
			postLogoutRedirectURI: "https://a.example.com",
			useGlobsClient:        true,
			wantErr:               false,
		},
		{
			name:                  "glob no match (HasRedirectGlobs)",
			registered:            []string{"https://logged-out"},
			registeredGlobs:       []string{"https://*.example.com"},
			applicationType:       op.ApplicationTypeWeb,
			postLogoutRedirectURI: "https://a.other.com",
			useGlobsClient:        true,
			wantErr:               true,
		},

		// RFC 8252 §7.3 endorsed examples (verbatim).
		// "An example redirect using the IPv4 loopback interface with a randomly
		//  assigned port: http://127.0.0.1:51004/oauth2redirect/example-provider"
		{
			name:                  "RFC 8252 §7.3 IPv4 example",
			registered:            []string{"http://127.0.0.1/oauth2redirect/example-provider"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:51004/oauth2redirect/example-provider",
			wantErr:               false,
		},
		// "An example redirect using the IPv6 loopback interface with a randomly
		//  assigned port: http://[::1]:61023/oauth2redirect/example-provider"
		{
			name:                  "RFC 8252 §7.3 IPv6 example",
			registered:            []string{"http://[::1]/oauth2redirect/example-provider"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://[::1]:61023/oauth2redirect/example-provider",
			wantErr:               false,
		},
		// RFC 8252 §7.3: "Clients SHOULD NOT assume that the device supports a
		// particular version of the Internet Protocol. It is RECOMMENDED that
		// clients attempt to bind to the loopback interface using both IPv4 and
		// IPv6 and use whichever is available." A client that registered the IPv4
		// form must therefore be able to log out via the IPv6 form (and vice versa).
		{
			name:                  "RFC 8252 §7.3 IPv6 request against IPv4 registration",
			registered:            []string{"http://127.0.0.1/oauth2redirect/example-provider"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://[::1]:61023/oauth2redirect/example-provider",
			wantErr:               false,
		},
		{
			name:                  "RFC 8252 §7.3 IPv4 request against IPv6 registration",
			registered:            []string{"http://[::1]/oauth2redirect/example-provider"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:51004/oauth2redirect/example-provider",
			wantErr:               false,
		},

		// RFC 8252 §7.3: "The authorization server MUST allow any port to be
		// specified at the time of the request for loopback IP redirect URIs."
		// Exercise the full ephemeral port range — minimum, max, and the port the
		// client would have if it bound to the system default.
		{
			name:                  "RFC 8252 §7.3 MUST allow any port — port 1",
			registered:            []string{"http://127.0.0.1/cb"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:1/cb",
			wantErr:               false,
		},
		{
			name:                  "RFC 8252 §7.3 MUST allow any port — port 80",
			registered:            []string{"http://127.0.0.1/cb"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:80/cb",
			wantErr:               false,
		},
		{
			name:                  "RFC 8252 §7.3 MUST allow any port — port 65535",
			registered:            []string{"http://127.0.0.1/cb"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:65535/cb",
			wantErr:               false,
		},
		{
			// Registration with an explicit port should still accept any other
			// port at request time — the spec says "any port", not "any port that
			// differs from the registered one".
			name:                  "RFC 8252 §7.3 registered explicit port, request different port",
			registered:            []string{"http://127.0.0.1:8080/cb"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://127.0.0.1:51004/cb",
			wantErr:               false,
		},

		// RFC 8252 §8.3: "While redirect URIs using localhost (i.e.,
		// http://localhost:{port}/{path}) function similarly to loopback IP
		// redirects described in Section 7.3, the use of localhost is NOT
		// RECOMMENDED." Functional must still hold even though it's discouraged.
		{
			name:                  "RFC 8252 §8.3 localhost variant (NOT RECOMMENDED but functional)",
			registered:            []string{"http://localhost/oauth2redirect/example-provider"},
			applicationType:       op.ApplicationTypeNative,
			postLogoutRedirectURI: "http://localhost:51004/oauth2redirect/example-provider",
			wantErr:               false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			var client op.Client
			if tt.useGlobsClient {
				m := mock.NewMockHasRedirectGlobs(ctrl)
				m.EXPECT().PostLogoutRedirectURIs().AnyTimes().Return(tt.registered)
				m.EXPECT().PostLogoutRedirectURIGlobs().AnyTimes().Return(tt.registeredGlobs)
				m.EXPECT().ApplicationType().AnyTimes().Return(tt.applicationType)
				client = m
			} else {
				m := mock.NewMockClient(ctrl)
				m.EXPECT().PostLogoutRedirectURIs().AnyTimes().Return(tt.registered)
				m.EXPECT().ApplicationType().AnyTimes().Return(tt.applicationType)
				client = m
			}
			err := op.ValidateEndSessionPostLogoutRedirectURI(tt.postLogoutRedirectURI, client)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

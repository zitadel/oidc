package op_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/schema"
)

func TestParseAuthenticatedTokenRequest(t *testing.T) {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	tests := []struct {
		name    string
		r       *http.Request
		wantErr error
	}{
		{
			name: "client_id+client_secret in body",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=myid&client_secret=mysecret")),
		},
		{
			name: "client_assertion only in body",
			r:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_assertion=xxx&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer")),
		},
		{
			name: "basic auth only",
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
				r.SetBasicAuth("myid", "mysecret")
				return r
			}(),
		},
		{
			name: "client_assertion and client_id+client_secret in body",
			r: httptest.NewRequest(http.MethodPost, "/",
				strings.NewReader("client_id=myid&client_secret=mysecret&client_assertion=xxx&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer")),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method"),
		},
		{
			name: "basic auth and client_assertion in body",
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/",
					strings.NewReader("client_assertion=xxx&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
				r.SetBasicAuth("myid", "mysecret")
				return r
			}(),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method"),
		},
		{
			name: "basic auth and client_id+client_secret in body",
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/",
					strings.NewReader("client_id=myid&client_secret=mysecret"))
				r.SetBasicAuth("myid", "mysecret")
				return r
			}(),
			wantErr: oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request := new(oidc.AccessTokenRequest)
			err := op.ParseAuthenticatedTokenRequest(tt.r, decoder, request)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr == nil {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthorizeCodeChallenge(t *testing.T) {
	tests := []struct {
		name          string
		codeVerifier  string
		codeChallenge *oidc.CodeChallenge
		want          func(t *testing.T, err error)
	}{
		{
			name:          "missing both code_verifier and code_challenge",
			codeVerifier:  "",
			codeChallenge: nil,
			want: func(t *testing.T, err error) {
				assert.Nil(t, err)
			},
		},
		{
			name:         "valid code_verifier",
			codeVerifier: "Hello World!",
			codeChallenge: &oidc.CodeChallenge{
				Challenge: "f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
				Method:    oidc.CodeChallengeMethodS256,
			},
			want: func(t *testing.T, err error) {
				assert.Nil(t, err)
			},
		},
		{
			name:         "invalid code_verifier",
			codeVerifier: "Hi World!",
			codeChallenge: &oidc.CodeChallenge{
				Challenge: "f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
				Method:    oidc.CodeChallengeMethodS256,
			},
			want: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "invalid code_verifier")
			},
		},
		{
			name:          "code_verifier provided without code_challenge",
			codeVerifier:  "code_verifier",
			codeChallenge: nil,
			want: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "code_verifier unexpectedly provided")
			},
		},
		{
			name:         "empty code_verifier",
			codeVerifier: "",
			codeChallenge: &oidc.CodeChallenge{
				Challenge: "f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
				Method:    oidc.CodeChallengeMethodS256,
			},
			want: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "code_verifier required")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.AuthorizeCodeChallenge(tt.codeVerifier, tt.codeChallenge)

			tt.want(t, err)
		})
	}
}

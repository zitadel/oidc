package op_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/schema"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestValidateResourceIndicators(t *testing.T) {
	tests := []struct {
		name      string
		resources []string
		wantErr   bool
	}{
		{
			name:      "no resource",
			resources: nil,
		},
		{
			name:      "absolute URI",
			resources: []string{"https://mcp.example.com/mcp"},
		},
		{
			name:      "multiple absolute URIs",
			resources: []string{"https://mcp.example.com/mcp", "urn:example:resource"},
		},
		{
			name:      "query component is allowed",
			resources: []string{"https://mcp.example.com/mcp?tenant=1"},
		},
		{
			name:      "empty value",
			resources: []string{""},
			wantErr:   true,
		},
		{
			name:      "relative reference",
			resources: []string{"/mcp"},
			wantErr:   true,
		},
		{
			name:      "missing scheme",
			resources: []string{"mcp.example.com/mcp"},
			wantErr:   true,
		},
		{
			name:      "fragment component",
			resources: []string{"https://mcp.example.com/mcp#fragment"},
			wantErr:   true,
		},
		{
			name:      "empty fragment component",
			resources: []string{"https://mcp.example.com/mcp#"},
			wantErr:   true,
		},
		{
			name:      "second value invalid",
			resources: []string{"https://mcp.example.com/mcp", "not a uri"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.ValidateResourceIndicators(tt.resources)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var oidcErr *oidc.Error
			require.ErrorAs(t, err, &oidcErr)
			assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
		})
	}
}

// resourceRequest is a minimal op.TokenRequest which reports and narrows
// the granted resource indicators.
type resourceRequest struct {
	resources        []string
	currentResources []string
}

func (r *resourceRequest) GetSubject() string    { return "id1" }
func (r *resourceRequest) GetAudience() []string { return []string{"client1"} }
func (r *resourceRequest) GetScopes() []string   { return []string{"openid"} }
func (r *resourceRequest) GetResource() []string { return r.resources }
func (r *resourceRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
}

// plainRequest is an op.TokenRequest which implements neither op.ResourceRequest
// nor op.CurrentResourceSetter.
type plainRequest struct{}

func (r *plainRequest) GetSubject() string    { return "id1" }
func (r *plainRequest) GetAudience() []string { return []string{"client1"} }
func (r *plainRequest) GetScopes() []string   { return []string{"openid"} }

func TestValidateTokenRequestResources(t *testing.T) {
	tests := []struct {
		name        string
		requested   []string
		granted     []string
		wantErr     bool
		wantCurrent []string
	}{
		{
			name:    "no resource requested",
			granted: []string{"https://mcp.example.com/mcp"},
			wantErr: false,
		},
		{
			name:        "requested resource was granted",
			requested:   []string{"https://mcp.example.com/mcp"},
			granted:     []string{"https://mcp.example.com/mcp", "https://api.example.com"},
			wantCurrent: []string{"https://mcp.example.com/mcp"},
		},
		{
			name:        "all granted resources requested",
			requested:   []string{"https://mcp.example.com/mcp", "https://api.example.com"},
			granted:     []string{"https://mcp.example.com/mcp", "https://api.example.com"},
			wantCurrent: []string{"https://mcp.example.com/mcp", "https://api.example.com"},
		},
		{
			name:      "requested resource was not granted",
			requested: []string{"https://other.example.com"},
			granted:   []string{"https://mcp.example.com/mcp"},
			wantErr:   true,
		},
		{
			name:      "one of the requested resources was not granted",
			requested: []string{"https://mcp.example.com/mcp", "https://other.example.com"},
			granted:   []string{"https://mcp.example.com/mcp"},
			wantErr:   true,
		},
		{
			name:      "invalid syntax",
			requested: []string{"/mcp"},
			granted:   []string{"/mcp"},
			wantErr:   true,
		},
		{
			name:        "nothing granted accepts any valid resource",
			requested:   []string{"https://mcp.example.com/mcp"},
			granted:     nil,
			wantCurrent: []string{"https://mcp.example.com/mcp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &resourceRequest{resources: tt.granted}
			err := op.ValidateTokenRequestResources(tt.requested, request)
			if tt.wantErr {
				require.Error(t, err)
				var oidcErr *oidc.Error
				require.ErrorAs(t, err, &oidcErr)
				assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
				assert.Nil(t, request.currentResources)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCurrent, request.currentResources)
		})
	}
}

func TestValidateTokenRequestResources_withoutResourceInterfaces(t *testing.T) {
	require.NoError(t, op.ValidateTokenRequestResources(nil, &plainRequest{}))
	require.NoError(t, op.ValidateTokenRequestResources([]string{"https://mcp.example.com/mcp"}, &plainRequest{}))
	require.Error(t, op.ValidateTokenRequestResources([]string{"/mcp"}, &plainRequest{}))
}

func TestParseTokenRequestResource(t *testing.T) {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	const form = "client_id=myid&client_secret=mysecret&code=abc&refresh_token=xyz" +
		"&resource=https%3A%2F%2Fmcp.example.com%2Fmcp&resource=https%3A%2F%2Fapi.example.com"
	want := []string{"https://mcp.example.com/mcp", "https://api.example.com"}

	t.Run("authorization_code", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		got, err := op.ParseAccessTokenRequest(r, decoder)
		require.NoError(t, err)
		assert.Equal(t, want, got.Resource)
	})

	t.Run("refresh_token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		got, err := op.ParseRefreshTokenRequest(r, decoder)
		require.NoError(t, err)
		assert.Equal(t, want, got.Resource)
	})

	t.Run("client_credentials", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		got, err := op.ParseClientCredentialsRequest(r, decoder)
		require.NoError(t, err)
		assert.Equal(t, want, got.Resource)
	})
}

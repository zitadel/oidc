package op

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type boundKeyIDTokenRequest struct {
	scopes []string
	jkt    string
}

func (r boundKeyIDTokenRequest) GetAMR() []string       { return nil }
func (r boundKeyIDTokenRequest) GetAudience() []string  { return []string{"client"} }
func (r boundKeyIDTokenRequest) GetAuthTime() time.Time { return time.Time{} }
func (r boundKeyIDTokenRequest) GetClientID() string    { return "client" }
func (r boundKeyIDTokenRequest) GetScopes() []string    { return r.scopes }
func (r boundKeyIDTokenRequest) GetSubject() string     { return "subject" }

// plainIDTokenRequest does not implement BoundKeyRequest at all, modelling a
// storage that has not been updated for key binding.
type plainIDTokenRequest struct {
	boundKeyIDTokenRequest
}

type jktIDTokenRequest struct {
	boundKeyIDTokenRequest
}

func (r jktIDTokenRequest) GetDPoPJKT() string { return r.jkt }

func TestRequireBoundKeyConfirmation(t *testing.T) {
	confirmation := &oidc.Confirmation{JWK: []byte(`{"kty":"EC"}`)}
	openid := []string{oidc.ScopeOpenID}
	bound := []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}

	tests := []struct {
		name         string
		request      IDTokenRequest
		confirmation *oidc.Confirmation
		wantErr      bool
	}{
		{
			name:    "unbound request without confirmation is allowed",
			request: plainIDTokenRequest{boundKeyIDTokenRequest{scopes: openid}},
		},
		{
			name:         "bound request with confirmation is allowed",
			request:      jktIDTokenRequest{boundKeyIDTokenRequest{scopes: bound, jkt: "thumbprint"}},
			confirmation: confirmation,
		},
		{
			// The core downgrade case.
			name:    "bound_key scope without confirmation is rejected",
			request: jktIDTokenRequest{boundKeyIDTokenRequest{scopes: bound, jkt: "thumbprint"}},
			wantErr: true,
		},
		{
			name:    "bound_key scope on a non-BoundKeyRequest is ignored",
			request: plainIDTokenRequest{boundKeyIDTokenRequest{scopes: bound}},
		},
		{
			// Defends against a flow that drops bound_key from the scopes but
			// still has a persisted binding commitment.
			name:    "persisted jkt without the scope is rejected",
			request: jktIDTokenRequest{boundKeyIDTokenRequest{scopes: openid, jkt: "thumbprint"}},
			wantErr: true,
		},
		{
			name:    "no scope and no jkt is allowed",
			request: jktIDTokenRequest{boundKeyIDTokenRequest{scopes: openid}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireBoundKeyConfirmation(tt.request, tt.confirmation)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			var oidcErr *oidc.Error
			require.ErrorAs(t, err, &oidcErr)
			assert.Equal(t, oidc.ServerError, oidcErr.ErrorType)
		})
	}
}

// TestIDTokenClaimsCannotForgeConfirmation ensures a storage-supplied extra
// claim named "cnf" cannot fake a key binding on an unbound ID Token.
func TestIDTokenClaimsCannotForgeConfirmation(t *testing.T) {
	claims := &oidc.IDTokenClaims{
		Claims: map[string]any{"cnf": map[string]any{"jwk": map[string]any{"kty": "EC"}}},
	}

	// Mirrors what createIDToken does before signing.
	delete(claims.Claims, "cnf")

	marshalled, err := claims.MarshalJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(marshalled), "cnf")
}

// legacyAuthRequest models an authorization request from a storage written
// before key binding existed: it has no GetDPoPJKT method.
type legacyAuthRequest struct {
	boundKeyIDTokenRequest
}

func TestLegacyStorageCannotBreakOnBoundKey(t *testing.T) {
	request := legacyAuthRequest{boundKeyIDTokenRequest{
		scopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey},
	}}

	_, integrated := keyBindingIntegrated(request)
	require.False(t, integrated)

	jkt, err := boundKeyThumbprint(request)
	require.NoError(t, err)
	assert.Empty(t, jkt, "no binding should be attempted")
	assert.NoError(t, requireBoundKeyConfirmation(request, nil))

	integratedRequest := jktIDTokenRequest{boundKeyIDTokenRequest{
		scopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey},
	}}
	_, err = boundKeyThumbprint(integratedRequest)
	require.Error(t, err)
	assert.Error(t, requireBoundKeyConfirmation(integratedRequest, nil))
}

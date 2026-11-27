package op_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// refreshRequest is a RefreshTokenRequest that records the current scopes.
type refreshRequest struct {
	op.RefreshTokenRequest
	scopes        []string
	currentScopes []string
}

func (r *refreshRequest) GetScopes() []string { return r.scopes }

func (r *refreshRequest) SetCurrentScopes(scopes []string) { r.currentScopes = scopes }

func TestValidateRefreshTokenScopes(t *testing.T) {
	granted := []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeOfflineAccess}
	tests := []struct {
		name      string
		requested []string
		wantErr   bool
		// wantCurrent is the narrowed set of scopes, nil when the scopes of
		// the original grant are kept.
		wantCurrent []string
	}{
		{name: "omitted", requested: nil},
		// scope= decodes to a single empty value, which is treated as omitted
		// (RFC 6749, section 3.2).
		{name: "empty", requested: []string{""}},
		{name: "only spaces", requested: []string{"", ""}},
		{
			name:        "narrowed",
			requested:   []string{oidc.ScopeOpenID},
			wantCurrent: []string{oidc.ScopeOpenID},
		},
		{
			name:        "repeated spaces between scopes",
			requested:   []string{oidc.ScopeOpenID, "", oidc.ScopeEmail},
			wantCurrent: []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		},
		{name: "not granted", requested: []string{oidc.ScopeOpenID, oidc.ScopeProfile}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &refreshRequest{scopes: granted}
			err := op.ValidateRefreshTokenScopes(tt.requested, req)
			if tt.wantErr {
				require.ErrorIs(t, err, oidc.ErrInvalidScope())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCurrent, req.currentScopes)
		})
	}
}

package op_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestGetTokenIDAndSubjectFromToken_OpaqueAccessToken(t *testing.T) {
	ctx := context.Background()

	// Opaque access tokens are stored as the encrypted string "tokenID:subject"
	// and have no JWT claims attached. This used to panic because the returned
	// claims pointer was dereferenced unconditionally.
	token, err := testProvider.Crypto().Encrypt("tokenID:subject")
	require.NoError(t, err)

	var (
		tokenIDOrToken, subject string
		claims                  map[string]any
		ok                      bool
	)
	require.NotPanics(t, func() {
		tokenIDOrToken, subject, claims, ok = op.GetTokenIDAndSubjectFromToken(ctx, testProvider, token, oidc.AccessTokenType, false)
	})

	assert.True(t, ok)
	assert.Equal(t, "tokenID", tokenIDOrToken)
	assert.Equal(t, "subject", subject)
	assert.Empty(t, claims)
}

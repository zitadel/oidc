package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	mcpResource = "https://mcp.example.com/mcp"
	apiResource = "https://api.example.com"
)

func TestAuthRequestResources(t *testing.T) {
	t.Run("without resource the audience is the client_id", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{ClientID: "web"}, "id1")
		assert.Empty(t, authReq.GetResource())
		assert.Equal(t, []string{"web"}, authReq.GetAudience())
		assert.Equal(t, []string{"web"}, op.AccessTokenAudience(authReq))
	})

	t.Run("the requested resources are added to the access token audience only", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: "web",
			Resource: []string{mcpResource, apiResource},
		}, "id1")
		assert.Equal(t, []string{mcpResource, apiResource}, authReq.GetResource())
		assert.Equal(t, []string{"web"}, authReq.GetAudience(), "ID token audience")
		assert.Equal(t, []string{"web", mcpResource, apiResource}, op.AccessTokenAudience(authReq))
	})

	t.Run("a token request narrows the access token audience down", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: "web",
			Resource: []string{mcpResource, apiResource},
		}, "id1")
		require.NoError(t, op.ValidateTokenRequestResources([]string{mcpResource}, authReq))
		assert.Equal(t, []string{"web", mcpResource}, op.AccessTokenAudience(authReq))
		assert.Equal(t, []string{"web"}, authReq.GetAudience(), "ID token audience")
		assert.Equal(t, []string{mcpResource, apiResource}, authReq.GetResource(), "the grant is kept")
	})
}

// TestRefreshTokenResourceGrant follows RFC 8707, section 2.2: an access token
// may be narrowed down to some of the granted resources, whereas the refresh token
// stays bound to the full original grant.
func TestRefreshTokenResourceGrant(t *testing.T) {
	ctx := context.Background()
	s := NewStorage(NewUserStore("https://localhost:9998/"))

	authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:    "web",
		RedirectURI: "https://example.com/callback",
		Scopes:      oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
		Resource:    []string{mcpResource, apiResource},
	}, "id1")
	require.NoError(t, err)

	// the code exchange asks for the MCP server only
	require.NoError(t, op.ValidateTokenRequestResources([]string{mcpResource}, authReq))
	accessTokenID, refreshToken, _, err := s.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)

	assert.Equal(t, []string{"web", mcpResource}, s.tokens[accessTokenID].Audience)
	stored := s.refreshTokens[refreshToken]
	assert.Equal(t, []string{mcpResource, apiResource}, stored.Resource)
	assert.Equal(t, []string{"web"}, stored.Audience)

	// a refresh request may ask for the other granted resource
	request, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"web"}, request.GetAudience(), "ID token audience")
	require.NoError(t, op.ValidateTokenRequestResources([]string{apiResource}, request))
	assert.Equal(t, []string{mcpResource, apiResource}, stored.Resource, "narrowing must not change the stored grant")

	accessTokenID, newRefreshToken, _, err := s.CreateAccessAndRefreshTokens(ctx, request, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"web", apiResource}, s.tokens[accessTokenID].Audience)
	assert.Equal(t, []string{mcpResource, apiResource}, s.refreshTokens[newRefreshToken].Resource)

	// without a resource parameter the access token is valid for the full grant
	request, err = s.TokenRequestByRefreshToken(ctx, newRefreshToken)
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources(nil, request))
	assert.Equal(t, []string{"web", mcpResource, apiResource}, op.AccessTokenAudience(request))

	// but not for a resource that was never granted
	err = op.ValidateTokenRequestResources([]string{"https://other.example.com"}, request)
	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
}

// TestRefreshTokenWithoutResourceGrant makes sure that a grant without resources
// does not allow a refresh request to pick an arbitrary resource.
func TestRefreshTokenWithoutResourceGrant(t *testing.T) {
	ctx := context.Background()
	s := NewStorage(NewUserStore("https://localhost:9998/"))

	authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:    "web",
		RedirectURI: "https://example.com/callback",
		Scopes:      oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
	}, "id1")
	require.NoError(t, err)

	// neither the code exchange
	err = op.ValidateTokenRequestResources([]string{mcpResource}, authReq)
	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)

	_, refreshToken, _, err := s.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)

	// nor the refresh request
	request, err := s.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	err = op.ValidateTokenRequestResources([]string{mcpResource}, request)
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
	assert.Equal(t, []string{"web"}, op.AccessTokenAudience(request))
}

// TestTokenAudiences checks the audience of the issued tokens: the resources are
// part of the access token audience, while the ID token stays addressed to the
// client.
func TestTokenAudiences(t *testing.T) {
	ctx := op.ContextWithIssuer(context.Background(), "https://localhost:9998/")
	s := NewStorageWithClients(NewUserStore("https://localhost:9998/"), map[string]*Client{
		"web": WebClient("web", "secret", "https://example.com/callback"),
	})
	client, err := s.GetClientByClientID(ctx, "web")
	require.NoError(t, err)

	authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:    "web",
		RedirectURI: "https://example.com/callback",
		Scopes:      oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		Resource:    []string{mcpResource, apiResource},
	}, "id1")
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{mcpResource}, authReq))

	accessToken, err := op.CreateJWT(ctx, "https://localhost:9998/", authReq, time.Now().Add(time.Minute), "token1", client, s)
	require.NoError(t, err)
	accessClaims := new(oidc.AccessTokenClaims)
	_, err = oidc.ParseToken(accessToken, accessClaims)
	require.NoError(t, err)
	assert.Equal(t, oidc.Audience{"web", mcpResource}, accessClaims.Audience)

	idToken, err := op.CreateIDToken(ctx, "https://localhost:9998/", authReq, time.Minute, "", "", s, client)
	require.NoError(t, err)
	idClaims := new(oidc.IDTokenClaims)
	_, err = oidc.ParseToken(idToken, idClaims)
	require.NoError(t, err)
	assert.Equal(t, oidc.Audience{"web"}, idClaims.Audience)
}

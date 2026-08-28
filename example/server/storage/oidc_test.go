package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAuthRequestResources(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)

	t.Run("without resource the audience is the client_id", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{ClientID: "web"}, "id1")
		assert.Empty(t, authReq.GetResource())
		assert.Equal(t, []string{"web"}, authReq.GetAudience())
	})

	t.Run("the requested resources are added to the audience", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: "web",
			Resource: []string{mcp, api},
		}, "id1")
		assert.Equal(t, []string{mcp, api}, authReq.GetResource())
		assert.Equal(t, []string{"web", mcp, api}, authReq.GetAudience())
	})

	t.Run("a token request narrows the audience down", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: "web",
			Resource: []string{mcp, api},
		}, "id1")
		authReq.SetCurrentResources([]string{mcp})
		assert.Equal(t, []string{"web", mcp}, authReq.GetAudience())
	})
}

func TestRefreshTokenRequestResources(t *testing.T) {
	const mcp = "https://mcp.example.com/mcp"

	request := RefreshTokenRequestFromBusiness(&RefreshToken{
		ApplicationID: "web",
		Audience:      []string{"web", mcp},
		Resource:      []string{mcp},
	})
	assert.Equal(t, []string{"web", mcp}, request.GetAudience())

	// a refresh request without any resource keeps the granted audience
	stored := RefreshTokenRequestFromBusiness(&RefreshToken{
		ApplicationID: "web",
		Audience:      []string{"web", mcp},
	})
	assert.Equal(t, []string{"web", mcp}, stored.GetAudience())
}

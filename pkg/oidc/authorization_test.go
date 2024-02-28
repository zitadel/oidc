//go:build go1.20

package oidc

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthRequest_LogValue(t *testing.T) {
	a := &AuthRequest{
		Scopes:       SpaceDelimitedArray{"a", "b"},
		ResponseType: "respType",
		ClientID:     "123",
		RedirectURI:  "http://example.com/callback",
	}
	want := slog.GroupValue(
		slog.Any("scopes", SpaceDelimitedArray{"a", "b"}),
		slog.String("response_type", "respType"),
		slog.String("client_id", "123"),
		slog.String("redirect_uri", "http://example.com/callback"),
	)
	got := a.LogValue()
	assert.Equal(t, want, got)
}

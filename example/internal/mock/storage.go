package mock

import (
	"github.com/caos/oidc/pkg/oidc"
)

type Storage struct {
}

func (s *Storage) CreateAuthRequest(authReq *oidc.AuthRequest) error {
	authReq.ID = "id"
	return nil
}
func (s *Storage) GetClientByClientID(string) (oidc.Client, error) {
	return &ConfClient{}, nil
}
func (s *Storage) AuthRequestByCode(oidc.Client, string, string) (*oidc.AuthRequest, error) {
	return &oidc.AuthRequest{ID: "id"}, nil
}
func (s *Storage) AuthorizeClientIDSecret(string, string) (oidc.Client, error) {
	return &ConfClient{}, nil
}
func (s *Storage) AuthorizeClientIDCodeVerifier(string, string) (oidc.Client, error) {
	return &ConfClient{}, nil
}
func (s *Storage) DeleteAuthRequestAndCode(string, string) error {
	return nil
}

type ConfClient struct{}

func (c *ConfClient) Type() oidc.ClientType {
	return oidc.ClientTypeConfidential
}
func (c *ConfClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://localhost:9999/callback",
		"custom://callback",
	}
}

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}

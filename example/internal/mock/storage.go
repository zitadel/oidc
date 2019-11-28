package mock

import (
	"errors"

	"github.com/caos/oidc/pkg/oidc"
)

type Signer struct {
}

func (s *Signer) Sign(*oidc.IDTokenClaims) (string, error) {
	return "sdsa", nil
}

type Storage struct {
}

func (s *Storage) CreateAuthRequest(authReq *oidc.AuthRequest) error {
	authReq.ID = "id"
	return nil
}
func (s *Storage) GetClientByClientID(id string) (oidc.Client, error) {
	if id == "not" {
		return nil, errors.New("not found")
	}
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
func (s *Storage) AuthRequestByID(id string) (*oidc.AuthRequest, error) {
	if id == "none" {
		return nil, errors.New("not found")
	}
	var responseType oidc.ResponseType
	if id == "code" {
		responseType = oidc.ResponseTypeCode
	} else if id == "id" {
		responseType = oidc.ResponseTypeIDTokenOnly
	} else {
		responseType = oidc.ResponseTypeIDToken
	}
	return &oidc.AuthRequest{
		ResponseType: responseType,
		RedirectURI:  "/callback",
	}, nil
}

type ConfClient struct{}

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

func (c *ConfClient) ApplicationType() oidc.ApplicationType {
	return oidc.ApplicationTypeNative
}

package mock

import (
	"errors"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
)

type Storage struct {
}

type AuthRequest struct {
	ID           string
	ResponseType oidc.ResponseType
	RedirectURI  string
}

func (a *AuthRequest) GetACR() string {
	return ""
}

func (a *AuthRequest) GetAMR() []string {
	return []string{}
}

func (a *AuthRequest) GetAudience() []string {
	return []string{
		a.ID,
	}
}

func (a *AuthRequest) GetClientID() string {
	return ""
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetNonce() string {
	return ""
}

func (a *AuthRequest) GetRedirectURI() string {
	return ""
}

func (a *AuthRequest) GetResponseType() oidc.ResponseType {
	return a.ResponseType
}

func (a *AuthRequest) GetState() string {
	return ""
}

func (a *AuthRequest) GetSubject() string {
	return ""
}

func (s *Storage) CreateAuthRequest(authReq *oidc.AuthRequest) (op.AuthRequest, error) {
	return &AuthRequest{ID: "id"}, nil
}
func (s *Storage) GetClientByClientID(id string) (op.Client, error) {
	if id == "none" {
		return nil, errors.New("not found")
	}
	var appType op.ApplicationType
	if id == "web" {
		appType = op.ApplicationTypeWeb
	} else if id == "native" {
		appType = op.ApplicationTypeNative
	} else {
		appType = op.ApplicationTypeUserAgent
	}
	return &ConfClient{applicationType: appType}, nil
}
func (s *Storage) AuthRequestByCode(op.Client, string, string) (op.AuthRequest, error) {
	return &AuthRequest{ID: "native"}, nil
}
func (s *Storage) AuthorizeClientIDSecret(string, string) (op.Client, error) {
	return &ConfClient{}, nil
}
func (s *Storage) AuthorizeClientIDCodeVerifier(string, string) (op.Client, error) {
	return &ConfClient{}, nil
}
func (s *Storage) DeleteAuthRequestAndCode(string, string) error {
	return nil
}
func (s *Storage) AuthRequestByID(id string) (op.AuthRequest, error) {
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
	return &AuthRequest{
		ResponseType: responseType,
		RedirectURI:  "/callback",
	}, nil
}

func (s *Storage) GetSigningKey() (*jose.SigningKey, error) {
	return &jose.SigningKey{Algorithm: jose.HS256, Key: []byte("test")}, nil
}

type ConfClient struct {
	applicationType op.ApplicationType
}

func (c *ConfClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://localhost:9999/callback",
		"http://localhost:5556/auth/callback",
		"custom://callback",
	}
}

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}

func (c *ConfClient) ApplicationType() op.ApplicationType {
	return c.applicationType
}

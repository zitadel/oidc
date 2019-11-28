package op

import "github.com/caos/oidc/pkg/oidc"

type Storage interface {
	CreateAuthRequest(*oidc.AuthRequest) error
	GetClientByClientID(string) (oidc.Client, error)
	AuthRequestByID(string) (*oidc.AuthRequest, error)
	AuthRequestByCode(oidc.Client, string, string) (*oidc.AuthRequest, error)
	AuthorizeClientIDSecret(string, string) (oidc.Client, error)
	AuthorizeClientIDCodeVerifier(string, string) (oidc.Client, error)
	DeleteAuthRequestAndCode(string, string) error
}

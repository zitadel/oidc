package op

import (
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type Storage interface {
	CreateAuthRequest(*oidc.AuthRequest) (AuthRequest, error)
	GetClientByClientID(string) (Client, error)
	AuthRequestByID(string) (AuthRequest, error)
	AuthRequestByCode(Client, string, string) (AuthRequest, error)
	AuthorizeClientIDSecret(string, string) (Client, error)
	AuthorizeClientIDCodeVerifier(string, string) (Client, error)
	DeleteAuthRequestAndCode(string, string) error
	GetSigningKey() (*jose.SigningKey, error)
}

type AuthRequest interface {
	GetID() string
	GetACR() string
	GetAMR() []string
	GetAudience() []string
	GetClientID() string
	GetNonce() string
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetState() string
	GetSubject() string
}

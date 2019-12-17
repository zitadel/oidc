package op

import (
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type AuthStorage interface {
	CreateAuthRequest(*oidc.AuthRequest) (AuthRequest, error)
	AuthRequestByID(string) (AuthRequest, error)
	DeleteAuthRequest(string) error

	GetSigningKey() (*jose.SigningKey, error)
	GetKeySet() (*jose.JSONWebKeySet, error)
}

type OPStorage interface {
	GetClientByClientID(string) (Client, error)
	AuthorizeClientIDSecret(string, string) error
	GetUserinfoFromScopes([]string) (*oidc.Userinfo, error)
}

type Storage interface {
	AuthStorage
	OPStorage
}

type AuthRequest interface {
	GetID() string
	GetACR() string
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	// GetCode() string
	GetCodeChallenge() *oidc.CodeChallenge
	GetNonce() string
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetScopes() []string
	GetState() string
	GetSubject() string
}

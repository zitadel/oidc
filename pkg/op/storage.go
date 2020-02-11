package op

import (
	"context"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type AuthStorage interface {
	CreateAuthRequest(context.Context, *oidc.AuthRequest) (AuthRequest, error)
	AuthRequestByID(context.Context, string) (AuthRequest, error)
	DeleteAuthRequest(context.Context, string) error

	GetSigningKey(context.Context, chan<- jose.SigningKey, chan<- error, <-chan bool)
	GetKeySet(context.Context) (*jose.JSONWebKeySet, error)
	SaveNewKeyPair(context.Context) error
}

type OPStorage interface {
	GetClientByClientID(context.Context, string) (Client, error)
	AuthorizeClientIDSecret(context.Context, string, string) error
	GetUserinfoFromScopes(context.Context, []string) (*oidc.Userinfo, error)
}

type Storage interface {
	AuthStorage
	OPStorage
	Health(context.Context) error
}

type StorageNotFoundError interface {
	IsNotFound()
}

type AuthRequest interface {
	GetID() string
	GetACR() string
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetCodeChallenge() *oidc.CodeChallenge
	GetNonce() string
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetScopes() []string
	GetState() string
	GetSubject() string
	Done() bool
}

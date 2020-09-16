package op

import (
	"context"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type AuthStorage interface {
	CreateAuthRequest(context.Context, *oidc.AuthRequest, string) (AuthRequest, error)
	AuthRequestByID(context.Context, string) (AuthRequest, error)
	AuthRequestByCode(context.Context, string) (AuthRequest, error)
	SaveAuthCode(context.Context, string, string) error
	DeleteAuthRequest(context.Context, string) error

	CreateToken(context.Context, TokenRequest) (string, time.Time, error)

	TerminateSession(context.Context, string, string) error

	GetSigningKey(context.Context, chan<- jose.SigningKey, chan<- error, <-chan time.Time)
	GetKeySet(context.Context) (*jose.JSONWebKeySet, error)
	SaveNewKeyPair(context.Context) error
}

type OPStorage interface {
	GetClientByClientID(context.Context, string) (Client, error)
	AuthorizeClientIDSecret(context.Context, string, string) error
	GetUserinfoFromScopes(context.Context, string, []string) (*oidc.Userinfo, error)
	GetUserinfoFromToken(context.Context, string, string) (*oidc.Userinfo, error)
	GetKeyByIDAndUserID(ctx context.Context, keyID, userID string) (*jose.JSONWebKey, error)
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

type EndSessionRequest struct {
	UserID      string
	Client      Client
	RedirectURI string
}

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

	CreateAccessToken(context.Context, TokenRequest) (string, time.Time, error)
	CreateAccessAndRefreshTokens(ctx context.Context, request TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error)
	TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (RefreshTokenRequest, error)

	TerminateSession(ctx context.Context, userID string, clientID string) error
	RevokeToken(ctx context.Context, token string, userID string, clientID string) *oidc.Error

	GetSigningKey(context.Context, chan<- jose.SigningKey)
	GetKeySet(context.Context) (*jose.JSONWebKeySet, error)
}

type OPStorage interface {
	GetClientByClientID(ctx context.Context, clientID string) (Client, error)
	AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error
	SetUserinfoFromScopes(ctx context.Context, userinfo oidc.UserInfoSetter, userID, clientID string, scopes []string) error
	SetUserinfoFromToken(ctx context.Context, userinfo oidc.UserInfoSetter, tokenID, subject, origin string) error
	SetIntrospectionFromToken(ctx context.Context, userinfo oidc.IntrospectionResponse, tokenID, subject, clientID string) error
	GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]interface{}, error)
	GetKeyByIDAndUserID(ctx context.Context, keyID, userID string) (*jose.JSONWebKey, error)
	ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error)
}

type Storage interface {
	AuthStorage
	OPStorage
	Health(context.Context) error
}

type StorageNotFoundError interface {
	IsNotFound()
}

type EndSessionRequest struct {
	UserID      string
	Client      Client
	RedirectURI string
}

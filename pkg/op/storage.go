package op

import (
	"context"
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type AuthStorage interface {
	CreateAuthRequest(context.Context, *oidc.AuthRequest, string) (AuthRequest, error)
	AuthRequestByID(context.Context, string) (AuthRequest, error)
	AuthRequestByCode(context.Context, string) (AuthRequest, error)
	SaveAuthCode(context.Context, string, string) error
	DeleteAuthRequest(context.Context, string) error

	// The TokenRequest parameter of CreateAccessToken can be any of:
	//
	// * TokenRequest as returned by ClientCredentialsStorage.ClientCredentialsTokenRequest,
	//
	// * AuthRequest as returned by AuthRequestByID or AuthRequestByCode (above)
	//
	// * *oidc.JWTTokenRequest from a JWT that is the assertion value of a JWT Profile
	//   Grant: https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
	CreateAccessToken(context.Context, TokenRequest) (accessTokenID string, expiration time.Time, err error)

	// The TokenRequest parameter of CreateAccessAndRefreshTokens can be any of:
	//
	// * TokenRequest as returned by ClientCredentialsStorage.ClientCredentialsTokenRequest
	//
	// * RefreshTokenRequest as returned by AuthStorage.TokenRequestByRefreshToken
	//
	// * AuthRequest as by returned by the AuthRequestByID or AuthRequestByCode (above).
	//   Used for the authorization code flow which requested offline_access scope and
	//   registered the refresh_token grant type in advance
	CreateAccessAndRefreshTokens(ctx context.Context, request TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshTokenID string, expiration time.Time, err error)
	TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (RefreshTokenRequest, error)

	TerminateSession(ctx context.Context, userID string, clientID string) error

	// RevokeToken should revoke a token. In the situation that the original request was to
	// revoke an access token, then tokenOrTokenID will be a tokenID and userID will be set
	// but if the original request was for a refresh token, then userID will be empty and
	// tokenOrTokenID will be the refresh token, not its ID.
	RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error

	SigningKey(context.Context) (SigningKey, error)
	SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error)
	KeySet(context.Context) ([]Key, error)
}

type ClientCredentialsStorage interface {
	ClientCredentials(ctx context.Context, clientID, clientSecret string) (Client, error)
	ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (TokenRequest, error)
}

// CanRefreshTokenInfo is an optional additional interface that Storage can support.
// Supporting CanRefreshTokenInfo is required to be able to (revoke) a refresh token that
// is neither an encrypted string of <tokenID>:<userID> nor a JWT.
type CanRefreshTokenInfo interface {
	// GetRefreshTokenInfo must return ErrInvalidRefreshToken when presented
	// with a token that is not a refresh token.
	GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error)
}

var ErrInvalidRefreshToken = errors.New("invalid_refresh_token")

type OPStorage interface {
	GetClientByClientID(ctx context.Context, clientID string) (Client, error)
	AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error
	SetUserinfoFromScopes(ctx context.Context, userinfo oidc.UserInfoSetter, userID, clientID string, scopes []string) error
	SetUserinfoFromToken(ctx context.Context, userinfo oidc.UserInfoSetter, tokenID, subject, origin string) error
	SetIntrospectionFromToken(ctx context.Context, userinfo oidc.IntrospectionResponse, tokenID, subject, clientID string) error
	GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]interface{}, error)

	// GetKeyByIDAndUserID is mis-named.  It does not pass userID.  Instead
	// it passes the clientID.
	GetKeyByIDAndUserID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error)
	ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error)
}

// JWTProfileTokenStorage is an additional, optional storage to implement
// implementing it, allows specifying the [AccessTokenType] of the access_token returned form the JWT Profile TokenRequest
type JWTProfileTokenStorage interface {
	JWTProfileTokenType(ctx context.Context, request TokenRequest) (AccessTokenType, error)
}

// Storage is a required parameter for NewOpenIDProvider(). In addition to the
// embedded interfaces below, if the passed Storage implements ClientCredentialsStorage
// then the grant type "client_credentials" will be supported. In that case, the access
// token returned by CreateAccessToken should be a JWT.
// See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4 for context.
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
	ClientID    string
	RedirectURI string
}

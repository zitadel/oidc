package op

import (
	"context"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/pkg/oidc"
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
	//
	// * TokenExchangeRequest
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
	//
	// * TokenExchangeRequest
	CreateAccessAndRefreshTokens(ctx context.Context, request TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshTokenID string, expiration time.Time, err error)
	TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (RefreshTokenRequest, error)

	TerminateSession(ctx context.Context, userID string, clientID string) error

	// RevokeToken should revoke a token. In the situation that the original request was to
	// revoke an access token, then tokenOrTokenID will be a tokenID and userID will be set
	// but if the original request was for a refresh token, then userID will be empty and
	// tokenOrTokenID will be the refresh token, not its ID.
	RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error

	GetSigningKey(context.Context, chan<- jose.SigningKey)
	GetKeySet(context.Context) (*jose.JSONWebKeySet, error)
}

type ClientCredentialsStorage interface {
	ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (TokenRequest, error)
}

type TokenExchangeStorage interface {
	// ValidateTokenExchangeRequest will be called to validate parsed (including tokens) Token Exchange Grant request.
	//
	// Important validations can include:
	// - permissions
	// - set requested token type to some default value if it is empty (rfc 8693 allows it) using SetRequestedTokenType method.
	//   Depending on RequestedTokenType - the following tokens will be issued:
	//   - RefreshTokenType - both access and refresh tokens
	//   - AccessTokenType - only access token
	//   - IDTokenType - only id token
	// - validation of subject's token type on possibility to be exchanged to the requested token type (according to your requirements)
	// - scopes (and update them using SetCurrentScopes method)
	// - set new subject if it differs from exchange subject (impersonation flow)
	//
	// Request will include subject's and/or actor's token claims if correspinding tokens are access/id_token issued by op
	// or third party tokens parsed by TokenExchangeTokensVerifierStorage interface methods.
	ValidateTokenExchangeRequest(ctx context.Context, request TokenExchangeRequest) error

	// CreateTokenExchangeRequest will be called after parsing and validating token exchange request.
	// Stored request is not accessed later by op - so it is up to implementer to decide
	// should this method actually store the request or not (common use case - store for it for audit purposes)
	CreateTokenExchangeRequest(ctx context.Context, request TokenExchangeRequest) error

	// GetPrivateClaimsFromTokenExchangeRequest will be called during access token creation.
	// Claims evaluation can be based on all validated request data available, including: scopes, resource, audience, etc.
	GetPrivateClaimsFromTokenExchangeRequest(ctx context.Context, request TokenExchangeRequest) (claims map[string]interface{}, err error)

	// SetUserinfoFromTokenExchangeRequest will be called during id token creation.
	// Claims evaluation can be based on all validated request data available, including: scopes, resource, audience, etc.
	SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo oidc.UserInfoSetter, request TokenExchangeRequest) error
}

// TokenExchangeTokensVerifierStorage is an optional interface used in token exchange process to verify tokens
// issued by third-party applications. If interface is not implemented - only tokens issued by op will be exchanged.
type TokenExchangeTokensVerifierStorage interface {
	VerifyExchangeSubjectToken(ctx context.Context, token string, tokenType oidc.TokenType) (tokenIDOrToken string, subject string, tokenClaims map[string]interface{}, err error)
	VerifyExchangeActorToken(ctx context.Context, token string, tokenType oidc.TokenType) (tokenIDOrToken string, actor string, tokenClaims map[string]interface{}, err error)
}

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

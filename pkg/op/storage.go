package op

import (
	"context"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/oidc"
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
	// * TokenExchangeRequest as returned by ValidateTokenExchangeRequest
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
	// * TokenExchangeRequest as returned by ValidateTokenExchangeRequest
	//
	// CreateAccessAndRefreshToken creates both access and refresh tokens.
	// The returned refresh token is the actual token value that will be passed
	// directly to the client. The storage implementation is responsible for
	// creating the complete refresh token (JWT or opaque format). For refresh tokens,
	// in either format, the token itself serves as both the identifier and the credential.
	CreateAccessAndRefreshTokens(ctx context.Context, request TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error)
	TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (RefreshTokenRequest, error)

	TerminateSession(ctx context.Context, userID string, clientID string) error

	// RevokeToken should revoke a token. In the situation that the original request was to
	// revoke an access token, then tokenOrTokenID will be a tokenID and userID will be set
	// but if the original request was for a refresh token, then userID will be empty and
	// tokenOrTokenID will be the refresh token, not its ID.  RevokeToken depends upon GetRefreshTokenInfo
	// to get information from refresh tokens that are not either "<tokenID>:<userID>" strings
	// nor JWTs.
	RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error

	// GetRefreshTokenInfo must return ErrInvalidRefreshToken when presented
	// with a token that is not a refresh token.
	GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error)

	SigningKey(context.Context) (SigningKey, error)
	SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error)
	KeySet(context.Context) ([]Key, error)
}

// CanTerminateSessionFromRequest is an optional additional interface that may be implemented by
// implementors of Storage as an alternative to TerminateSession of the AuthStorage.
// It passes the complete parsed EndSessionRequest to the implementation, which allows access to additional data.
// It also allows to modify the uri, which will be used for redirection, (e.g. a UI where the user can consent to the logout)
type CanTerminateSessionFromRequest interface {
	TerminateSessionFromRequest(ctx context.Context, endSessionRequest *EndSessionRequest) (string, error)
}

type ClientCredentialsStorage interface {
	ClientCredentials(ctx context.Context, clientID, clientSecret string) (Client, error)
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
	GetPrivateClaimsFromTokenExchangeRequest(ctx context.Context, request TokenExchangeRequest) (claims map[string]any, err error)

	// SetUserinfoFromTokenExchangeRequest will be called during id token creation.
	// Claims evaluation can be based on all validated request data available, including: scopes, resource, audience, etc.
	SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *oidc.UserInfo, request TokenExchangeRequest) error
}

// TokenExchangeTokensVerifierStorage is an optional interface used in token exchange process to verify tokens
// issued by third-party applications. If interface is not implemented - only tokens issued by op will be exchanged.
type TokenExchangeTokensVerifierStorage interface {
	VerifyExchangeSubjectToken(ctx context.Context, token string, tokenType oidc.TokenType) (tokenIDOrToken string, subject string, tokenClaims map[string]any, err error)
	VerifyExchangeActorToken(ctx context.Context, token string, tokenType oidc.TokenType) (tokenIDOrToken string, actor string, tokenClaims map[string]any, err error)
}

var ErrInvalidRefreshToken = errors.New("invalid_refresh_token")

type OPStorage interface {
	// GetClientByClientID loads a Client. The returned Client is never cached and is only used to
	// handle the current request.
	GetClientByClientID(ctx context.Context, clientID string) (Client, error)
	AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error
	// SetUserinfoFromScopes is deprecated and should have an empty implementation for now.
	// Implement SetUserinfoFromRequest instead.
	SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error
	SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error
	SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID, subject, clientID string) error
	GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error)
	GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error)
	ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error)
}

// JWTProfileTokenStorage is an additional, optional storage to implement
// implementing it, allows specifying the [AccessTokenType] of the access_token returned form the JWT Profile TokenRequest
type JWTProfileTokenStorage interface {
	JWTProfileTokenType(ctx context.Context, request TokenRequest) (AccessTokenType, error)
}

// CanSetUserinfoFromRequest is an optional additional interface that may be implemented by
// implementors of Storage.  It allows additional data to be set in id_tokens based on the
// request.
type CanSetUserinfoFromRequest interface {
	SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request IDTokenRequest, scopes []string) error
}

// CanGetPrivateClaimsFromRequest is an optional additional interface that may be implemented by
// implementors of Storage. It allows setting the jwt token claims based on the request.
type CanGetPrivateClaimsFromRequest interface {
	GetPrivateClaimsFromRequest(ctx context.Context, request TokenRequest, restrictedScopes []string) (map[string]any, error)
}

// Storage is a required parameter for NewOpenIDProvider().
//
// In addition to the embedded interfaces below,
//
//   - if the passed Storage implements ClientCredentialsStorage then the grant type "client_credentials" will be
//     supported. In that case, the access token returned by CreateAccessToken should be a JWT.
//   - if the passed Storage implemenets ClientsStorage, then dynamic client registration will be supported.
//
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
	UserID            string
	ClientID          string
	IDTokenHintClaims *oidc.IDTokenClaims
	RedirectURI       string
	LogoutHint        string
	UILocales         []language.Tag
}

var ErrDuplicateUserCode = errors.New("user code already exists")

type DeviceAuthorizationStorage interface {
	// StoreDeviceAuthorizationRequest stores a new device authorization request in the database.
	// User code will be used by the user to complete the login flow and must be unique.
	// ErrDuplicateUserCode signals the caller should try again with a new code.
	//
	// Note that user codes are low entropy keys and when many exist in the
	// database, the change for collisions increases. Therefore implementers
	// of this interface must make sure that user codes of expired authentication flows are purged,
	// after some time.
	StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error

	// GetDeviceAuthorizatonState returns the current state of the device authorization flow in the database.
	// The method is polled untill the the authorization is eighter Completed, Expired or Denied.
	GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*DeviceAuthorizationState, error)
}

func assertDeviceStorage(s Storage) (DeviceAuthorizationStorage, error) {
	storage, ok := s.(DeviceAuthorizationStorage)
	if !ok {
		return nil, oidc.ErrUnsupportedGrantType().WithDescription("device_code grant not supported")
	}
	return storage, nil
}

var (
	ErrInvalidClient                  = errors.New("invalid client")
	ErrInvalidRegistrationAccessToken = errors.New("invalid registration access token")
	ErrClientNoPermission             = errors.New("client no permission")
	ErrInvalidRedirectURI             = errors.New("invalid redirect_uri")
	ErrInvalidClientMetadata          = errors.New("invalid client metadata")
	ErrInvalidSoftwareStatement       = errors.New("invalid software statement")
	ErrUnapprovedSoftwareStatement    = errors.New("unapproved software statement")
	ErrInvalidInitialAccessToken      = errors.New("invalid initial access token")
	ErrClientUpdateNotAllowed         = errors.New("client update not allowed")
	ErrClientDeleteNotSupported       = errors.New("client delete not supported")
	ErrClientDeleteNotAllowed         = errors.New("client delete not allowed")
)

// ClientsStorage is required to implement dynamic client registration.
type ClientsStorage interface {
	// RegisterClient handles the Client Registration Request according to [RFC7591].
	//
	// If the value of one or more redirection URIs is invalid, return an ErrInvalidRedirectURI.
	//
	// If the value of one of the client metadata fields is invalid and the server has rejected this request,
	// return an ErrInvalidClientMetadata.
	//
	// [RFC7591]: https://www.rfc-editor.org/rfc/rfc7591#section-3.1
	RegisterClient(ctx context.Context, c *oidc.ClientRegistrationRequest) (*oidc.ClientRegistrationResponse, error)

	// ReadClient handles the Client Read Request according to [RFC7592].
	//
	// If the Client does not exist on this server,
	// or the Client is invalid, return an ErrInvalidClient.
	//
	// [RFC7592]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1
	ReadClient(ctx context.Context, clientID string) (*oidc.ClientReadResponse, error)

	// UpdateClient handles the Client Update Request according to [RFC7592].
	//
	// If the Client does not exist on this server,
	// or the Client is invalid, return an ErrInvalidClient.
	//
	// If the value of one or more redirection URIs is invalid, return an ErrInvalidRedirectURI.
	//
	// If the value of one of the client metadata fields is invalid and the server has rejected this request,
	// return an ErrInvalidClientMetadata.
	//
	// If the client is not allowed to update its records, return an ErrClientUpdateNotAllowed.
	//
	// [RFC7592]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.2
	UpdateClient(ctx context.Context, c *oidc.ClientUpdateRequest) (*oidc.ClientInformationResponse, error)

	// DeleteClient handles the Client Delete Request according to [RFC7592].
	//
	// If the Client does not exist on this server,
	// or the Client is invalid, return an ErrInvalidClient.
	//
	// If the server does not support the delete method, return ErrClientDeleteNotSupported.
	//
	// If the client is not allowed to delete itself, return ErrClientDeleteNotAllowed.
	//
	// [RFC7592]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.3
	DeleteClient(ctx context.Context, clientID string) error

	// AuthorizeClientRegistration will check if a Client Registration Request ([RFC7591]) is authorized by parsing
	// either:
	//
	//	- an initial access token (OAuth 2.0 access token optionally issued by an authorization server to a developer
	//		or client and used to authorize calls to the client registration endpoint.), or
	//	- a software statement (A digitally signed or MACed JSON Web Token (JWT) [RFC7519] that asserts metadata
	// 		values about the client software.)
	//
	// If the initial access token is invalid, return an ErrInvalidInitialAccessToken.
	//
	// If the software statement is invalid, return an ErrInvalidSoftwareStatement.
	//
	// If the software statement presented is not approved for use by this authorization server, return an
	// ErrUnapprovedSoftwareStatement.
	//
	// [RFC7591]: https://www.rfc-editor.org/rfc/rfc7591
	// [RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
	AuthorizeClientRegistration(ctx context.Context, initialAccessToken string, c *oidc.ClientRegistrationRequest) error

	// AuthorizeClientRead will check if a Client Read Request ([RFC7592]) is authorized for
	// [Protected Dynamic Client Registration].
	//
	// If the Client does not exist on this server,
	// or the Client is invalid, return an ErrInvalidClient.
	//
	// If the Registration Access Token used is invalid, return an ErrInvalidRegistrationAccessToken.
	//
	// If the Client does not have permission to read its record,
	// return an ErrClientNoPermission.
	//
	// [RFC7592]: https://www.rfc-editor.org/rfc/rfc7592
	// [Protected Dynamic Client Registration]: https://www.rfc-editor.org/rfc/rfc7591#appendix-A.1.2
	AuthorizeClientRead(ctx context.Context, clientID, registrationAccessToken string) error

	// AuthorizeClientUpdate will check if a Client Update Request ([RFC7592]) is authorized.
	//
	// If the Client does not exist on this server,
	// or the Client is invalid, return an ErrInvalidClient.
	//
	// If the Registration Access Token used is invalid, return an ErrInvalidRegistrationAccessToken.
	//
	// If the Client does not have permission to read its record,
	// return an ErrClientNoPermission.
	//
	// [RFC7592]: https://www.rfc-editor.org/rfc/rfc7592
	AuthorizeClientUpdate(ctx context.Context, clientID, registrationAccessToken string) error

	// AuthorizeClientDelete will check if a Client Delete Request ([RFC7592]) is authorized.
	//
	// If the Client does not exist on this server,
	// or the Client is invalid, return an ErrInvalidClient.
	//
	// If the Registration Access Token used is invalid, return an ErrInvalidRegistrationAccessToken.
	//
	// If the Client does not have permission to read its record,
	// return an ErrClientNoPermission.
	//
	// [RFC7592]: https://www.rfc-editor.org/rfc/rfc7592
	AuthorizeClientDelete(ctx context.Context, clientID, registrationAccessToken string) error
}

func assertClientStorage(s Storage) (ClientsStorage, error) {
	storage, ok := s.(ClientsStorage)
	if !ok {
		return nil, oidc.ErrUnsupportedGrantType().WithDescription("Dynamic client registration not supported")
	}
	return storage, nil
}

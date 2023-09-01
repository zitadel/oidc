package op

import (
	"context"
	"net/http"
	"net/url"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type Exchanger interface {
	Storage() Storage
	Decoder() httphelper.Decoder
	Crypto() Crypto
	AuthMethodPostSupported() bool
	AuthMethodPrivateKeyJWTSupported() bool
	GrantTypeRefreshTokenSupported() bool
	GrantTypeTokenExchangeSupported() bool
	GrantTypeJWTAuthorizationSupported() bool
	GrantTypeClientCredentialsSupported() bool
	GrantTypeDeviceCodeSupported() bool
	AccessTokenVerifier(context.Context) AccessTokenVerifier
	IDTokenHintVerifier(context.Context) IDTokenHintVerifier
}

func tokenHandler(exchanger Exchanger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "tokenHandler")
		defer span.End()

		Exchange(w, r.WithContext(ctx), exchanger)
	}
}

// Exchange performs a token exchange appropriate for the grant type
func Exchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	grantType := r.FormValue("grant_type")
	switch grantType {
	case string(oidc.GrantTypeCode):
		CodeExchange(w, r, exchanger)
		return
	case string(oidc.GrantTypeRefreshToken):
		if exchanger.GrantTypeRefreshTokenSupported() {
			RefreshTokenExchange(w, r, exchanger)
			return
		}
	case string(oidc.GrantTypeBearer):
		if ex, ok := exchanger.(JWTAuthorizationGrantExchanger); ok && exchanger.GrantTypeJWTAuthorizationSupported() {
			JWTProfile(w, r, ex)
			return
		}
	case string(oidc.GrantTypeTokenExchange):
		if exchanger.GrantTypeTokenExchangeSupported() {
			TokenExchange(w, r, exchanger)
			return
		}
	case string(oidc.GrantTypeClientCredentials):
		if exchanger.GrantTypeClientCredentialsSupported() {
			ClientCredentialsExchange(w, r, exchanger)
			return
		}
	case string(oidc.GrantTypeDeviceCode):
		if exchanger.GrantTypeDeviceCodeSupported() {
			DeviceAccessToken(w, r, exchanger)
			return
		}
	case "":
		RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("grant_type missing"))
		return
	}
	RequestError(w, r, oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType))
}

// AuthenticatedTokenRequest is a helper interface for ParseAuthenticatedTokenRequest
// it is implemented by oidc.AuthRequest and oidc.RefreshTokenRequest
type AuthenticatedTokenRequest interface {
	SetClientID(string)
	SetClientSecret(string)
}

// ParseAuthenticatedTokenRequest parses the client_id and client_secret from the HTTP request from either
// HTTP Basic Auth header or form body and sets them into the provided authenticatedTokenRequest interface
func ParseAuthenticatedTokenRequest(r *http.Request, decoder httphelper.Decoder, request AuthenticatedTokenRequest) error {
	ctx, span := tracer.Start(r.Context(), "ParseAuthenticatedTokenRequest")
	defer span.End()
	r = r.WithContext(ctx)

	err := r.ParseForm()
	if err != nil {
		return oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	err = decoder.Decode(request, r.Form)
	if err != nil {
		return oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil
	}
	clientID, err = url.QueryUnescape(clientID)
	if err != nil {
		return oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
	}
	clientSecret, err = url.QueryUnescape(clientSecret)
	if err != nil {
		return oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
	}
	request.SetClientID(clientID)
	request.SetClientSecret(clientSecret)
	return nil
}

// AuthorizeClientIDSecret authorizes a client by validating the client_id and client_secret (Basic Auth and POST)
func AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string, storage Storage) error {
	err := storage.AuthorizeClientIDSecret(ctx, clientID, clientSecret)
	if err != nil {
		return oidc.ErrInvalidClient().WithDescription("invalid client_id / client_secret").WithParent(err)
	}
	return nil
}

// AuthorizeCodeChallenge authorizes a client by validating the code_verifier against the previously sent
// code_challenge of the auth request (PKCE)
func AuthorizeCodeChallenge(tokenReq *oidc.AccessTokenRequest, challenge *oidc.CodeChallenge) error {
	if tokenReq.CodeVerifier == "" {
		return oidc.ErrInvalidRequest().WithDescription("code_challenge required")
	}
	if !oidc.VerifyCodeChallenge(challenge, tokenReq.CodeVerifier) {
		return oidc.ErrInvalidGrant().WithDescription("invalid code challenge")
	}
	return nil
}

// AuthorizePrivateJWTKey authorizes a client by validating the client_assertion's signature with a previously
// registered public key (JWT Profile)
func AuthorizePrivateJWTKey(ctx context.Context, clientAssertion string, exchanger JWTAuthorizationGrantExchanger) (Client, error) {
	ctx, span := tracer.Start(ctx, "AuthorizePrivateJWTKey")
	defer span.End()

	jwtReq, err := VerifyJWTAssertion(ctx, clientAssertion, exchanger.JWTProfileVerifier(ctx))
	if err != nil {
		return nil, err
	}
	client, err := exchanger.Storage().GetClientByClientID(ctx, jwtReq.Issuer)
	if err != nil {
		return nil, err
	}
	if client.AuthMethod() != oidc.AuthMethodPrivateKeyJWT {
		return nil, oidc.ErrInvalidClient()
	}
	return client, nil
}

// ValidateGrantType ensures that the requested grant_type is allowed by the client
func ValidateGrantType(client interface{ GrantTypes() []oidc.GrantType }, grantType oidc.GrantType) bool {
	if client == nil {
		return false
	}
	for _, grant := range client.GrantTypes() {
		if grantType == grant {
			return true
		}
	}
	return false
}

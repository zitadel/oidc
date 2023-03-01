package op

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

//go:generate go get github.com/dmarkham/enumer
//go:generate go run github.com/dmarkham/enumer -linecomment -sql -json -text -yaml -gqlgen -type=ApplicationType,AccessTokenType
//go:generate go mod tidy

const (
	ApplicationTypeWeb       ApplicationType = iota // web
	ApplicationTypeUserAgent                        // user_agent
	ApplicationTypeNative                           // native
)

const (
	AccessTokenTypeBearer AccessTokenType = iota // bearer
	AccessTokenTypeJWT                           // JWT
)

type ApplicationType int

type AuthMethod string

type AccessTokenType int

type Client interface {
	GetID() string
	RedirectURIs() []string
	PostLogoutRedirectURIs() []string
	ApplicationType() ApplicationType
	AuthMethod() oidc.AuthMethod
	ResponseTypes() []oidc.ResponseType
	GrantTypes() []oidc.GrantType
	LoginURL(string) string
	AccessTokenType() AccessTokenType
	IDTokenLifetime() time.Duration
	DevMode() bool
	RestrictAdditionalIdTokenScopes() func(scopes []string) []string
	RestrictAdditionalAccessTokenScopes() func(scopes []string) []string
	IsScopeAllowed(scope string) bool
	IDTokenUserinfoClaimsAssertion() bool
	ClockSkew() time.Duration
}

func ContainsResponseType(types []oidc.ResponseType, responseType oidc.ResponseType) bool {
	for _, t := range types {
		if t == responseType {
			return true
		}
	}
	return false
}

func IsConfidentialType(c Client) bool {
	return c.ApplicationType() == ApplicationTypeWeb
}

var (
	ErrInvalidAuthHeader   = errors.New("invalid basic auth header")
	ErrNoClientCredentials = errors.New("no client credentials provided")
	ErrMissingClientID     = errors.New("client_id missing from request")
)

type ClientJWTProfile interface {
	JWTProfileVerifier(context.Context) JWTProfileVerifier
}

func ClientJWTAuth(ctx context.Context, ca oidc.ClientAssertionParams, verifier ClientJWTProfile) (clientID string, err error) {
	if ca.ClientAssertion == "" {
		return "", oidc.ErrInvalidClient().WithParent(ErrNoClientCredentials)
	}

	profile, err := VerifyJWTAssertion(ctx, ca.ClientAssertion, verifier.JWTProfileVerifier(ctx))
	if err != nil {
		return "", oidc.ErrUnauthorizedClient().WithParent(err).WithDescription("JWT assertion failed")
	}
	return profile.Issuer, nil
}

func ClientBasicAuth(r *http.Request, storage Storage) (clientID string, err error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return "", oidc.ErrInvalidClient().WithParent(ErrNoClientCredentials)
	}
	clientID, err = url.QueryUnescape(clientID)
	if err != nil {
		return "", oidc.ErrInvalidClient().WithParent(ErrInvalidAuthHeader)
	}
	clientSecret, err = url.QueryUnescape(clientSecret)
	if err != nil {
		return "", oidc.ErrInvalidClient().WithParent(ErrInvalidAuthHeader)
	}
	if err := storage.AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
		return "", oidc.ErrUnauthorizedClient().WithParent(err)
	}
	return clientID, nil
}

type ClientProvider interface {
	Decoder() httphelper.Decoder
	Storage() Storage
}

type clientData struct {
	ClientID string `schema:"client_id"`
	oidc.ClientAssertionParams
}

// ClientIDFromRequest parses the request form and tries to obtain the client ID
// and reports if it is authenticated, using a JWT or static client secrets over
// http basic auth.
//
// If the Provider implements IntrospectorJWTProfile and "client_assertion" is
// present in the form data, JWT assertion will be verified and the
// client ID is taken from there.
// If any of them is absent, basic auth is attempted.
// In absence of basic auth data, the unauthenticated client id from the form
// data is returned.
//
// If no client id can be obtained by any method, oidc.ErrInvalidClient
// is returned with ErrMissingClientID wrapped in it.
func ClientIDFromRequest(r *http.Request, p ClientProvider) (clientID string, authenticated bool, err error) {
	err = r.ParseForm()
	if err != nil {
		return "", false, oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	data := new(clientData)
	if err = p.Decoder().Decode(data, r.PostForm); err != nil {
		return "", false, err
	}

	JWTProfile, ok := p.(ClientJWTProfile)
	if ok {
		clientID, err = ClientJWTAuth(r.Context(), data.ClientAssertionParams, JWTProfile)
	}
	if !ok || errors.Is(err, ErrNoClientCredentials) {
		clientID, err = ClientBasicAuth(r, p.Storage())
	}
	if err == nil {
		return clientID, true, nil
	}

	if data.ClientID == "" {
		return "", false, oidc.ErrInvalidClient().WithParent(ErrMissingClientID)
	}
	return data.ClientID, false, nil
}

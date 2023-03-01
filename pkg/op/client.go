package op

import (
	"time"

	"github.com/zitadel/oidc/pkg/oidc"
)

//go:generate go get github.com/dmarkham/enumer
//go:generate go run github.com/dmarkham/enumer -linecomment -sql -json -text -yaml -gqlgen -type=ApplicationType,AccessTokenType

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

// HasRedirectGlobs is an optional interface that can be implemented by implementors of
// Client. See https://pkg.go.dev/github.com/gobwas/glob#Compile for glob
// interpretation. Redirect URIs that match either the non-glob version or the
// glob version will be accepted. Glob URIs are only partially supported for native
// clients: "http://" is not allowed except for loopback or in dev mode.
type HasRedirectGlobs interface {
	RedirectURIGlobs() []string
	PostLogoutRedirectURIGlobs() []string
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

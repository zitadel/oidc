package op

import (
	"time"

	"github.com/caos/oidc/pkg/oidc"
)

const (
	ApplicationTypeWeb ApplicationType = iota
	ApplicationTypeUserAgent
	ApplicationTypeNative
)

const (
	AccessTokenTypeBearer AccessTokenType = iota
	AccessTokenTypeJWT
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

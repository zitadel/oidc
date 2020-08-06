package op

import (
	"github.com/caos/oidc/pkg/oidc"
	"time"
)

const (
	ApplicationTypeWeb ApplicationType = iota
	ApplicationTypeUserAgent
	ApplicationTypeNative

	AccessTokenTypeBearer AccessTokenType = iota
	AccessTokenTypeJWT
)

type Client interface {
	GetID() string
	RedirectURIs() []string
	PostLogoutRedirectURIs() []string
	ApplicationType() ApplicationType
	AuthMethod() AuthMethod
	ResponseTypes() []oidc.ResponseType
	LoginURL(string) string
	AccessTokenType() AccessTokenType
	IDTokenLifetime() time.Duration
	DevMode() bool
}

func IsConfidentialType(c Client) bool {
	return c.ApplicationType() == ApplicationTypeWeb
}

func ContainsResponseType(types []oidc.ResponseType, responseType oidc.ResponseType) bool {
	for _, t := range types {
		if t == responseType {
			return true
		}
	}
	return false
}

type ApplicationType int

type AuthMethod string

type AccessTokenType int

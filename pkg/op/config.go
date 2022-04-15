package op

import (
	"errors"
	"net/url"
	"os"

	"golang.org/x/text/language"
)

const OidcDevMode = "CAOS_OIDC_DEV"

type Configuration interface {
	Issuer() string
	AuthorizationEndpoint() Endpoint
	TokenEndpoint() Endpoint
	IntrospectionEndpoint() Endpoint
	UserinfoEndpoint() Endpoint
	RevocationEndpoint() Endpoint
	EndSessionEndpoint() Endpoint
	KeysEndpoint() Endpoint

	AuthMethodPostSupported() bool
	CodeMethodS256Supported() bool
	AuthMethodPrivateKeyJWTSupported() bool
	TokenEndpointSigningAlgorithmsSupported() []string
	GrantTypeRefreshTokenSupported() bool
	GrantTypeTokenExchangeSupported() bool
	GrantTypeJWTAuthorizationSupported() bool
	GrantTypeClientCredentialsSupported() bool
	IntrospectionAuthMethodPrivateKeyJWTSupported() bool
	IntrospectionEndpointSigningAlgorithmsSupported() []string
	RevocationAuthMethodPrivateKeyJWTSupported() bool
	RevocationEndpointSigningAlgorithmsSupported() []string
	RequestObjectSupported() bool
	RequestObjectSigningAlgorithmsSupported() []string

	SupportedUILocales() []language.Tag
}

func ValidateIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("missing issuer")
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return errors.New("invalid url for issuer")
	}
	if u.Host == "" {
		return errors.New("host for issuer missing")
	}
	if u.Scheme != "https" {
		if !devLocalAllowed(u) {
			return errors.New("scheme for issuer must be `https`")
		}
	}
	if u.Fragment != "" || len(u.Query()) > 0 {
		return errors.New("no fragments or query allowed for issuer")
	}
	return nil
}

func devLocalAllowed(url *url.URL) bool {
	_, b := os.LookupEnv(OidcDevMode)
	if !b {
		return b
	}
	return url.Scheme == "http"
}

package op

import (
	"errors"
	"net/url"
	"os"
	"strings"

	"golang.org/x/text/language"
)

const OidcDevMode = "CAOS_OIDC_DEV"

type Configuration interface {
	Issuer() string
	AuthorizationEndpoint() Endpoint
	TokenEndpoint() Endpoint
	IntrospectionEndpoint() Endpoint
	UserinfoEndpoint() Endpoint
	EndSessionEndpoint() Endpoint
	KeysEndpoint() Endpoint

	AuthMethodPostSupported() bool
	CodeMethodS256Supported() bool
	AuthMethodPrivateKeyJWTSupported() bool
	GrantTypeRefreshTokenSupported() bool
	GrantTypeTokenExchangeSupported() bool
	GrantTypeJWTAuthorizationSupported() bool

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
	return url.Scheme == "http" &&
		url.Host == "localhost" ||
		url.Host == "127.0.0.1" ||
		url.Host == "::1" ||
		strings.HasPrefix(url.Host, "localhost:")
}

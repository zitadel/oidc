package op

import (
	"errors"
	"net/url"
	"os"
	"strings"
)

type Configuration interface {
	Issuer() string
	AuthorizationEndpoint() Endpoint
	TokenEndpoint() Endpoint
	UserinfoEndpoint() Endpoint
	KeysEndpoint() Endpoint

	AuthMethodPostSupported() bool

	Port() string
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
	_, b := os.LookupEnv("CAOS_OIDC_DEV")
	if !b {
		return b
	}
	return url.Scheme == "http" &&
		url.Host == "localhost" ||
		url.Host == "127.0.0.1" ||
		url.Host == "::1" ||
		strings.HasPrefix(url.Host, "localhost:")
}

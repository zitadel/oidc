package op

import (
	"errors"
	"net/url"
	"strings"
)

type Configuration interface {
	Issuer() string
	AuthorizationEndpoint() Endpoint
	TokenEndpoint() Endpoint
	UserinfoEndpoint() Endpoint
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
		if !(u.Scheme == "http" && (u.Host == "localhost" || u.Host == "127.0.0.1" || u.Host == "::1" || strings.HasPrefix(u.Host, "localhost:"))) { //TODO: ?
			return errors.New("scheme for issuer must be `https`")
		}
	}
	if u.Fragment != "" || len(u.Query()) > 0 {
		return errors.New("no fragments or query allowed for issuer")
	}
	return nil
}

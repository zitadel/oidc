package op

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/text/language"
)

var (
	ErrInvalidIssuerPath        = errors.New("no fragments or query allowed for issuer")
	ErrInvalidIssuerNoIssuer    = errors.New("missing issuer")
	ErrInvalidIssuerURL         = errors.New("invalid url for issuer")
	ErrInvalidIssuerMissingHost = errors.New("host for issuer missing")
	ErrInvalidIssuerHTTPS       = errors.New("scheme for issuer must be `https`")
)

type Configuration interface {
	IssuerFromRequest(r *http.Request) string
	Insecure() bool
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
	IntrospectionAuthMethodPrivateKeyJWTSupported() bool
	IntrospectionEndpointSigningAlgorithmsSupported() []string
	RevocationAuthMethodPrivateKeyJWTSupported() bool
	RevocationEndpointSigningAlgorithmsSupported() []string
	RequestObjectSupported() bool
	RequestObjectSigningAlgorithmsSupported() []string

	SupportedUILocales() []language.Tag
}

type IssuerFromRequest func(r *http.Request) string

func IssuerFromHost(path string) func(bool) (IssuerFromRequest, error) {
	return func(allowInsecure bool) (IssuerFromRequest, error) {
		issuerPath, err := url.Parse(path)
		if err != nil {
			return nil, ErrInvalidIssuerURL
		}
		if err := ValidateIssuerPath(issuerPath); err != nil {
			return nil, err
		}
		return func(r *http.Request) string {
			return dynamicIssuer(r.Host, path, allowInsecure)
		}, nil
	}
}

func StaticIssuer(issuer string) func(bool) (IssuerFromRequest, error) {
	return func(allowInsecure bool) (IssuerFromRequest, error) {
		if err := ValidateIssuer(issuer, allowInsecure); err != nil {
			return nil, err
		}
		return func(_ *http.Request) string {
			return issuer
		}, nil
	}
}

func ValidateIssuer(issuer string, allowInsecure bool) error {
	if issuer == "" {
		return ErrInvalidIssuerNoIssuer
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return ErrInvalidIssuerURL
	}
	if u.Host == "" {
		return ErrInvalidIssuerMissingHost
	}
	if u.Scheme != "https" {
		if !devLocalAllowed(u, allowInsecure) {
			return ErrInvalidIssuerHTTPS
		}
	}
	return ValidateIssuerPath(u)
}

func ValidateIssuerPath(issuer *url.URL) error {
	if issuer.Fragment != "" || len(issuer.Query()) > 0 {
		return ErrInvalidIssuerPath
	}
	return nil
}

func devLocalAllowed(url *url.URL, allowInsecure bool) bool {
	if !allowInsecure {
		return false
	}
	return url.Scheme == "http"
}

func dynamicIssuer(issuer, path string, allowInsecure bool) string {
	schema := "https"
	if allowInsecure {
		schema = "http"
	}
	if len(path) > 0 && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return schema + "://" + issuer + path
}

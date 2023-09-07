package op

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/muhlemmer/httpforwarded"
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
	DeviceAuthorizationEndpoint() Endpoint

	AuthMethodPostSupported() bool
	CodeMethodS256Supported() bool
	AuthMethodPrivateKeyJWTSupported() bool
	TokenEndpointSigningAlgorithmsSupported() []string
	GrantTypeRefreshTokenSupported() bool
	GrantTypeTokenExchangeSupported() bool
	GrantTypeJWTAuthorizationSupported() bool
	GrantTypeClientCredentialsSupported() bool
	GrantTypeDeviceCodeSupported() bool
	IntrospectionAuthMethodPrivateKeyJWTSupported() bool
	IntrospectionEndpointSigningAlgorithmsSupported() []string
	RevocationAuthMethodPrivateKeyJWTSupported() bool
	RevocationEndpointSigningAlgorithmsSupported() []string
	RequestObjectSupported() bool
	RequestObjectSigningAlgorithmsSupported() []string

	SupportedUILocales() []language.Tag
	DeviceAuthorization() DeviceAuthorizationConfig
}

type IssuerFromRequest func(r *http.Request) string

func IssuerFromHost(path string) func(bool) (IssuerFromRequest, error) {
	return issuerFromForwardedOrHost(path, false)
}

// IssuerFromForwardedOrHost tries to establish the Issuer based
// on the Forwarded header host field.
// If multiple Forwarded headers are present, the first mention
// of the host field will be used.
// If the Forwarded header is not present, no host field is found,
// or there is a parser error the Request Host will be used as a fallback.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
func IssuerFromForwardedOrHost(path string) func(bool) (IssuerFromRequest, error) {
	return issuerFromForwardedOrHost(path, true)
}

func issuerFromForwardedOrHost(path string, parseForwarded bool) func(bool) (IssuerFromRequest, error) {
	return func(allowInsecure bool) (IssuerFromRequest, error) {
		issuerPath, err := url.Parse(path)
		if err != nil {
			return nil, ErrInvalidIssuerURL
		}
		if err := ValidateIssuerPath(issuerPath); err != nil {
			return nil, err
		}
		return func(r *http.Request) string {
			if parseForwarded {
				if host, ok := hostFromForwarded(r); ok {
					return dynamicIssuer(host, path, allowInsecure)
				}
			}
			return dynamicIssuer(r.Host, path, allowInsecure)
		}, nil
	}
}

func hostFromForwarded(r *http.Request) (host string, ok bool) {
	fwd, err := httpforwarded.ParseFromRequest(r)
	if err != nil {
		log.Printf("Err: issuer from forwarded header: %v", err) // TODO change to slog on next branch
		return "", false
	}
	if fwd == nil || len(fwd["host"]) == 0 {
		return "", false
	}
	return fwd["host"][0], true
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

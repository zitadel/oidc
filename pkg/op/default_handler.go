package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/caos/oidc/pkg/utils"

	"github.com/caos/oidc/pkg/oidc"
)

type DefaultHandler struct {
	config          *Config
	discoveryConfig *oidc.DiscoveryConfiguration
	storage         Storage
	http            *http.Server
}

type Config struct {
	Issuer                string
	AuthorizationEndpoint Endpoint
	TokenEndpoint         Endpoint
	IntrospectionEndpoint Endpoint
	UserinfoEndpoint      Endpoint
	EndSessionEndpoint    Endpoint
	CheckSessionIframe    Endpoint
	JwksURI               Endpoint
	// ScopesSupported:                   oidc.SupportedScopes,
	// ResponseTypesSupported:            responseTypes,
	// GrantTypesSupported:               oidc.SupportedGrantTypes,
	// ClaimsSupported:                   oidc.SupportedClaims,
	// IdTokenSigningAlgValuesSupported:  []string{keys.SigningAlgorithm},
	// SubjectTypesSupported:             []string{"public"},
	// TokenEndpointAuthMethodsSupported:
	Port string
}

const (
	defaultAuthorizationEndpoint = "authorize"
	defaulTokenEndpoint          = "token"
	defaultIntrospectEndpoint    = "introspect"
	defaultUserinfoEndpoint      = "me"
)

func (c *Config) DefaultAndValidate() error {
	if err := ValidateIssuer(c.Issuer); err != nil {
		return err
	}
	if c.AuthorizationEndpoint == "" {
		c.AuthorizationEndpoint = defaultAuthorizationEndpoint
	}
	if c.TokenEndpoint == "" {
		c.TokenEndpoint = defaulTokenEndpoint
	}
	if c.IntrospectionEndpoint == "" {
		c.IntrospectionEndpoint = defaultIntrospectEndpoint
	}
	if c.UserinfoEndpoint == "" {
		c.UserinfoEndpoint = defaultUserinfoEndpoint
	}
	return nil
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

func OIDC(c Configuration) *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                c.Issuer(),
		AuthorizationEndpoint: c.AuthorizationEndpoint().Absolute(c.Issuer()),
		// TokenEndpoint:         c.absoluteEndpoint(c.TokenEndpoint),
		// IntrospectionEndpoint: c.absoluteEndpoint(c.IntrospectionEndpoint),
		// UserinfoEndpoint:      c.absoluteEndpoint(c.UserinfoEndpoint),
		// EndSessionEndpoint:    c.absoluteEndpoint(c.EndSessionEndpoint),
		// CheckSessionIframe:    c.absoluteEndpoint(c.CheckSessionIframe),
		// JwksURI:               c.absoluteEndpoint(c.JwksURI),
		// ScopesSupported:                   oidc.SupportedScopes,
		// ResponseTypesSupported:            responseTypes,
		// GrantTypesSupported:               oidc.SupportedGrantTypes,
		// ClaimsSupported:                   oidc.SupportedClaims,
		// IdTokenSigningAlgValuesSupported:  []string{keys.SigningAlgorithm},
		// SubjectTypesSupported:             []string{"public"},
		// TokenEndpointAuthMethodsSupported:

	}
}

func (c *Config) absoluteEndpoint(endpoint string) string {
	return strings.TrimSuffix(c.Issuer, "/") + relativeEndpoint(endpoint)
}

func absoluteEndpoint(host, endpoint string) string {
	return strings.TrimSuffix(host, "/") + relativeEndpoint(endpoint)
}

func relativeEndpoint(endpoint string) string {
	return "/" + strings.TrimPrefix(endpoint, "/")
}

func NewDefaultHandler(config *Config, storage Storage) (Handler, error) {
	err := config.DefaultAndValidate()
	if err != nil {
		return nil, err
	}
	h := &DefaultHandler{
		config:  config,
		storage: storage,
	}
	h.discoveryConfig = OIDC(h)
	router := CreateRouter(h)
	h.http = &http.Server{
		Addr:    ":" + config.Port,
		Handler: router,
	}

	return h, nil
}

func (h *DefaultHandler) Issuer() string {
	return h.config.Issuer
}

type Endpoint string

func (e Endpoint) Relative() string {
	return relativeEndpoint(string(e))
}

func (e Endpoint) Absolute(host string) string {
	return absoluteEndpoint(host, string(e))
}

func (e Endpoint) Validate() error {
	return nil //TODO:
}

func (h *DefaultHandler) AuthorizationEndpoint() Endpoint {
	return Endpoint(h.config.AuthorizationEndpoint)

}

func (h *DefaultHandler) TokenEndpoint() Endpoint {
	return Endpoint(h.config.TokenEndpoint)
}

func (h *DefaultHandler) UserinfoEndpoint() Endpoint {
	return Endpoint(h.config.UserinfoEndpoint)
}

func (h *DefaultHandler) Port() string {
	return h.config.Port
}

func (h *DefaultHandler) HttpHandler() *http.Server {
	return h.http
}

func (h *DefaultHandler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	utils.MarshalJSON(w, h.discoveryConfig)
}

func (h *DefaultHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	authRequest, err := ParseAuthRequest(w, r)
	if err != nil {
		//TODO: return err
	}
	err = ValidateAuthRequest(authRequest)
	if err != nil {
		//TODO: return err
	}
	if NeedsExistingSession(authRequest) {
		// session, err := h.storage.CheckSession(authRequest)
		// if err != nil {
		// 	//TODO: return err
		// }
	}
	err = h.storage.CreateAuthRequest(authRequest)
	if err != nil {
		//TODO: return err
	}
	//TODO: redirect?
}

func (h *DefaultHandler) HandleExchange(w http.ResponseWriter, r *http.Request) {
}

func (h *DefaultHandler) HandleUserinfo(w http.ResponseWriter, r *http.Request) {

}

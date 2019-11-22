package op

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/caos/oidc/pkg/utils"

	"github.com/caos/oidc/pkg/oidc"
)

type DefaultOP struct {
	config          *Config
	endpoints       *endpoints
	discoveryConfig *oidc.DiscoveryConfiguration
	storage         Storage
	http            *http.Server
}

type Config struct {
	Issuer string
	// ScopesSupported:                   oidc.SupportedScopes,
	// ResponseTypesSupported:            responseTypes,
	// GrantTypesSupported:               oidc.SupportedGrantTypes,
	// ClaimsSupported:                   oidc.SupportedClaims,
	// IdTokenSigningAlgValuesSupported:  []string{keys.SigningAlgorithm},
	// SubjectTypesSupported:             []string{"public"},
	// TokenEndpointAuthMethodsSupported:
	Port string
}

type endpoints struct {
	Authorization         Endpoint
	Token                 Endpoint
	IntrospectionEndpoint Endpoint
	Userinfo              Endpoint
	EndSessionEndpoint    Endpoint
	CheckSessionIframe    Endpoint
	JwksURI               Endpoint
}

type DefaultOPOpts func(o *DefaultOP) error

func WithCustomAuthEndpoint(endpoint Endpoint) DefaultOPOpts {
	return func(o *DefaultOP) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Authorization = endpoint
		return nil
	}
}

func WithCustomTokenEndpoint(endpoint Endpoint) DefaultOPOpts {
	return func(o *DefaultOP) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Token = endpoint
		return nil
	}
}

func WithCustomUserinfoEndpoint(endpoint Endpoint) DefaultOPOpts {
	return func(o *DefaultOP) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Userinfo = endpoint
		return nil
	}
}

const (
	defaultAuthorizationEndpoint = "authorize"
	defaulTokenEndpoint          = "oauth/token"
	defaultIntrospectEndpoint    = "introspect"
	defaultUserinfoEndpoint      = "userinfo"
)

func CreateDiscoveryConfig(c Configuration) *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                c.Issuer(),
		AuthorizationEndpoint: c.AuthorizationEndpoint().Absolute(c.Issuer()),
		TokenEndpoint:         c.TokenEndpoint().Absolute(c.Issuer()),
		// IntrospectionEndpoint: c.Intro().Absolute(c.Issuer()),
		UserinfoEndpoint: c.UserinfoEndpoint().Absolute(c.Issuer()),
		// EndSessionEndpoint: c.TokenEndpoint().Absolute(c.Issuer())(c.EndSessionEndpoint),
		// CheckSessionIframe: c.TokenEndpoint().Absolute(c.Issuer())(c.CheckSessionIframe),
		// JwksURI:            c.TokenEndpoint().Absolute(c.Issuer())(c.JwksURI),
		// ScopesSupported:                   oidc.SupportedScopes,
		// ResponseTypesSupported:            responseTypes,
		// GrantTypesSupported:               oidc.SupportedGrantTypes,
		// ClaimsSupported:                   oidc.SupportedClaims,
		// IdTokenSigningAlgValuesSupported:  []string{keys.SigningAlgorithm},
		// SubjectTypesSupported:             []string{"public"},
		// TokenEndpointAuthMethodsSupported:

	}
}

var DefaultEndpoints = &endpoints{
	Authorization:         defaultAuthorizationEndpoint,
	Token:                 defaulTokenEndpoint,
	IntrospectionEndpoint: defaultIntrospectEndpoint,
	Userinfo:              defaultUserinfoEndpoint,
}

func NewDefaultOP(config *Config, storage Storage, opOpts ...DefaultOPOpts) (OpenIDProvider, error) {
	if err := ValidateIssuer(config.Issuer); err != nil {
		return nil, err
	}

	p := &DefaultOP{
		config:    config,
		storage:   storage,
		endpoints: DefaultEndpoints,
	}

	for _, optFunc := range opOpts {
		if err := optFunc(p); err != nil {
			return nil, err
		}
	}

	p.discoveryConfig = CreateDiscoveryConfig(p)

	router := CreateRouter(p)
	p.http = &http.Server{
		Addr:    ":" + config.Port,
		Handler: router,
	}

	return p, nil
}

func (p *DefaultOP) Issuer() string {
	return p.config.Issuer
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

func (p *DefaultOP) AuthorizationEndpoint() Endpoint {
	return p.endpoints.Authorization

}

func (p *DefaultOP) TokenEndpoint() Endpoint {
	return Endpoint(p.endpoints.Token)
}

func (p *DefaultOP) UserinfoEndpoint() Endpoint {
	return Endpoint(p.endpoints.Userinfo)
}

func (p *DefaultOP) Port() string {
	return p.config.Port
}

func (p *DefaultOP) HttpHandler() *http.Server {
	return p.http
}

func (p *DefaultOP) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	utils.MarshalJSON(w, p.discoveryConfig)
}

func (p *DefaultOP) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	authRequest, err := ParseAuthRequest(w, r)
	if err != nil {
		//TODO: return err
	}
	err = ValidateAuthRequest(authRequest, p.storage)
	if err != nil {
		//TODO: return err
	}
	// err = p.storage.CreateAuthRequest(authRequest)
	// if err != nil {
	// 	//TODO: return err
	// }
	//TODO: redirect?
}

func (p *DefaultOP) HandleExchange(w http.ResponseWriter, r *http.Request) {
}

func (p *DefaultOP) HandleUserinfo(w http.ResponseWriter, r *http.Request) {

}

// func (c *Config) DefaultAndValidate() error {
// 	if err := ValidateIssuer(c.Issuer); err != nil {
// 		return err
// 	}
// 	if c.AuthorizationEndpoint == "" {
// 		c.AuthorizationEndpoint = defaultAuthorizationEndpoint
// 	}
// 	if c.TokenEndpoint == "" {
// 		c.TokenEndpoint = defaulTokenEndpoint
// 	}
// 	if c.IntrospectionEndpoint == "" {
// 		c.IntrospectionEndpoint = defaultIntrospectEndpoint
// 	}
// 	if c.UserinfoEndpoint == "" {
// 		c.UserinfoEndpoint = defaultUserinfoEndpoint
// 	}
// 	return nil
// }

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

func (c *Config) absoluteEndpoint(endpoint string) string {
	return strings.TrimSuffix(c.Issuer, "/") + relativeEndpoint(endpoint)
}

func absoluteEndpoint(host, endpoint string) string {
	return strings.TrimSuffix(host, "/") + relativeEndpoint(endpoint)
}

func relativeEndpoint(endpoint string) string {
	return "/" + strings.TrimPrefix(endpoint, "/")
}

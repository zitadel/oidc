package op

import (
	"net/http"
	"time"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
)

const (
	defaultAuthorizationEndpoint = "authorize"
	defaulTokenEndpoint          = "oauth/token"
	defaultIntrospectEndpoint    = "introspect"
	defaultUserinfoEndpoint      = "userinfo"
	defaultKeysEndpoint          = "keys"

	authMethodBasic = "client_secret_basic"
	authMethodPost  = "client_secret_post"
)

var (
	DefaultEndpoints = &endpoints{
		Authorization:         defaultAuthorizationEndpoint,
		Token:                 defaulTokenEndpoint,
		IntrospectionEndpoint: defaultIntrospectEndpoint,
		Userinfo:              defaultUserinfoEndpoint,
		JwksURI:               defaultKeysEndpoint,
	}
	DefaultIDTokenValidity = time.Duration(5 * time.Minute)
)

type DefaultOP struct {
	config          *Config
	endpoints       *endpoints
	discoveryConfig *oidc.DiscoveryConfiguration
	storage         Storage
	signer          Signer
	http            *http.Server
	decoder         *schema.Decoder
	encoder         *schema.Encoder
}

type Config struct {
	Issuer          string
	IDTokenValidity time.Duration
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

func NewDefaultOP(config *Config, authStorage AuthStorage, opStorage OPStorage, opOpts ...DefaultOPOpts) (OpenIDProvider, error) {
	err := ValidateIssuer(config.Issuer)
	if err != nil {
		return nil, err
	}

	storage := struct {
		AuthStorage
		OPStorage
	}{
		AuthStorage: authStorage,
		OPStorage:   opStorage,
	}

	p := &DefaultOP{
		config:    config,
		storage:   storage,
		endpoints: DefaultEndpoints,
	}

	p.signer, err = NewDefaultSigner(authStorage)
	if err != nil {
		return nil, err
	}

	for _, optFunc := range opOpts {
		if err := optFunc(p); err != nil {
			return nil, err
		}
	}

	p.discoveryConfig = CreateDiscoveryConfig(p, p.signer)

	router := CreateRouter(p)
	p.http = &http.Server{
		Addr:    ":" + config.Port,
		Handler: router,
	}
	p.decoder = schema.NewDecoder()
	p.decoder.IgnoreUnknownKeys(true)

	p.encoder = schema.NewEncoder()

	return p, nil
}

func (p *DefaultOP) Issuer() string {
	return p.config.Issuer
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

func (p *DefaultOP) KeysEndpoint() Endpoint {
	return Endpoint(p.endpoints.JwksURI)
}

func (p *DefaultOP) AuthMethodBasicSupported() bool {
	return true //TODO: config
}

func (p *DefaultOP) AuthMethodPostSupported() bool {
	return true //TODO: config
}

func (p *DefaultOP) Port() string {
	return p.config.Port
}

func (p *DefaultOP) HttpHandler() *http.Server {
	return p.http
}

func (p *DefaultOP) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	Discover(w, p.discoveryConfig)
}

func (p *DefaultOP) Decoder() *schema.Decoder {
	return p.decoder
}

func (p *DefaultOP) Encoder() *schema.Encoder {
	return p.encoder
}

func (p *DefaultOP) Storage() Storage {
	return p.storage
}

func (p *DefaultOP) Signer() Signer {
	return p.signer
	// return
}

func (p *DefaultOP) IDTokenValidity() time.Duration {
	if p.config.IDTokenValidity == 0 {
		p.config.IDTokenValidity = DefaultIDTokenValidity
	}
	return p.config.IDTokenValidity
}

// func (p *DefaultOP) ErrorHandler() func(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error) {
// 	return AuthRequestError
// }

func (p *DefaultOP) HandleKeys(w http.ResponseWriter, r *http.Request) {
	Keys(w, r, p)
}

func (p *DefaultOP) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	Authorize(w, r, p)
}

func (p *DefaultOP) HandleAuthorizeCallback(w http.ResponseWriter, r *http.Request) {
	AuthorizeCallback(w, r, p)
}

func (p *DefaultOP) HandleExchange(w http.ResponseWriter, r *http.Request) {
	reqType := r.FormValue("grant_type")
	if reqType == "" {
		ExchangeRequestError(w, r, ErrInvalidRequest("grant_type missing"))
		return
	}
	if reqType == string(oidc.GrantTypeCode) {
		CodeExchange(w, r, p)
		return
	}
	p.handleTokenExchange(w, r)
}

func (p *DefaultOP) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	ExchangeRequestError(w, r, ErrServerError("not implemented"))
	return
	tokenRequest, err := ParseTokenExchangeRequest(w, r)
	if err != nil {
		//TODO: return err
	}
	err = ValidateTokenExchangeRequest(tokenRequest, p.storage)
	if err != nil {
		//TODO: return err
	}
}

func (p *DefaultOP) HandleUserinfo(w http.ResponseWriter, r *http.Request) {

}

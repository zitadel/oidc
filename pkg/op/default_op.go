package op

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/schema"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/logging"
	"github.com/caos/oidc/pkg/oidc"
)

const (
	defaultAuthorizationEndpoint = "authorize"
	defaulTokenEndpoint          = "oauth/token"
	defaultIntrospectEndpoint    = "introspect"
	defaultUserinfoEndpoint      = "userinfo"
	defaultKeysEndpoint          = "keys"

	AuthMethodBasic AuthMethod = "client_secret_basic"
	AuthMethodPost             = "client_secret_post"
	AuthMethodNone             = "none"
)

var (
	DefaultEndpoints = &endpoints{
		Authorization:         defaultAuthorizationEndpoint,
		Token:                 defaulTokenEndpoint,
		IntrospectionEndpoint: defaultIntrospectEndpoint,
		Userinfo:              defaultUserinfoEndpoint,
		JwksURI:               defaultKeysEndpoint,
	}
)

type DefaultOP struct {
	config      *Config
	endpoints   *endpoints
	storage     Storage
	signer      Signer
	crypto      Crypto
	http        *http.Server
	decoder     *schema.Decoder
	encoder     *schema.Encoder
	interceptor HttpInterceptor
	retry       func(int) (bool, int)
}

type Config struct {
	Issuer    string
	CryptoKey [32]byte
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

func WithHttpInterceptor(h HttpInterceptor) DefaultOPOpts {
	return func(o *DefaultOP) error {
		o.interceptor = h
		return nil
	}
}

func WithRetry(max int, sleep time.Duration) DefaultOPOpts {
	return func(o *DefaultOP) error {
		o.retry = func(count int) (bool, int) {
			count++
			if count == max {
				return false, count
			}
			time.Sleep(sleep)
			return true, count
		}
		return nil
	}
}

func NewDefaultOP(ctx context.Context, config *Config, storage Storage, opOpts ...DefaultOPOpts) (OpenIDProvider, error) {
	err := ValidateIssuer(config.Issuer)
	if err != nil {
		return nil, err
	}

	p := &DefaultOP{
		config:    config,
		storage:   storage,
		endpoints: DefaultEndpoints,
	}

	keyCh := make(chan jose.SigningKey)
	// ctx, cancel := context.WithCancel(ctx)
	p.signer = NewDefaultSigner(ctx, storage, keyCh)
	go p.ensureKey(ctx, storage, keyCh)

	for _, optFunc := range opOpts {
		if err := optFunc(p); err != nil {
			return nil, err
		}
	}

	router := CreateRouter(p, p.interceptor)
	p.http = &http.Server{
		Addr:    ":" + config.Port,
		Handler: router,
	}
	p.decoder = schema.NewDecoder()
	p.decoder.IgnoreUnknownKeys(true)

	p.encoder = schema.NewEncoder()

	p.crypto = NewAESCrypto(config.CryptoKey)

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
	Discover(w, CreateDiscoveryConfig(p, p.Signer()))
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
}

func (p *DefaultOP) Crypto() Crypto {
	return p.crypto
}
func (p *DefaultOP) HandleReady(w http.ResponseWriter, r *http.Request) {
	probes := []ProbesFn{
		ReadySigner(p.Signer()),
		ReadyStorage(p.Storage()),
	}
	Readiness(w, r, probes...)
}

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
	TokenExchange(w, r, p)
}

func (p *DefaultOP) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	Userinfo(w, r, p)
}

func (p *DefaultOP) ensureKey(ctx context.Context, storage Storage, keyCh chan<- jose.SigningKey) {
	count := 0
	explicit := make(chan bool)
	errCh := make(chan error)
	go storage.GetSigningKey(ctx, keyCh, errCh, explicit)
	explicit <- true
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			if err == nil {
				continue
			}
			_, ok := err.(StorageNotFoundError)
			if ok {
				err := storage.SaveNewKeyPair(ctx)
				if err == nil {
					continue
				}
			}
			ok, count = p.retry(count)
			if ok {
				explicit <- true
				continue
			}
			logging.Log("OP-n6ynVE").WithError(err).Panic("error in key signer")
		}
	}
}

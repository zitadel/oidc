package op

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/schema"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/logging"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/rp"
	"github.com/caos/oidc/pkg/utils"
)

const (
	defaultAuthorizationEndpoint = "authorize"
	defaulTokenEndpoint          = "oauth/token"
	defaultIntrospectEndpoint    = "introspect"
	defaultUserinfoEndpoint      = "userinfo"
	defaultEndSessionEndpoint    = "end_session"
	defaultKeysEndpoint          = "keys"

	AuthMethodBasic AuthMethod = "client_secret_basic"
	AuthMethodPost             = "client_secret_post"
	AuthMethodNone             = "none"

	CodeMethodS256 = "S256"
)

var (
	DefaultEndpoints = &endpoints{
		Authorization: NewEndpoint(defaultAuthorizationEndpoint),
		Token:         NewEndpoint(defaulTokenEndpoint),
		Introspection: NewEndpoint(defaultIntrospectEndpoint),
		Userinfo:      NewEndpoint(defaultUserinfoEndpoint),
		EndSession:    NewEndpoint(defaultEndSessionEndpoint),
		JwksURI:       NewEndpoint(defaultKeysEndpoint),
	}
)

type DefaultOP struct {
	config       *Config
	endpoints    *endpoints
	storage      Storage
	signer       Signer
	verifier     IDTokenHintVerifier
	crypto       Crypto
	http         http.Handler
	decoder      *schema.Decoder
	encoder      *schema.Encoder
	interceptors []HttpInterceptor
	retry        func(int) (bool, int)
	timer        <-chan time.Time
}

type Config struct {
	Issuer                   string
	CryptoKey                [32]byte
	DefaultLogoutRedirectURI string
	CodeMethodS256           bool
	// ScopesSupported:                   oidc.SupportedScopes,
	// ResponseTypesSupported:            responseTypes,
	// GrantTypesSupported:               oidc.SupportedGrantTypes,
	// ClaimsSupported:                   oidc.SupportedClaims,
	// IdTokenSigningAlgValuesSupported:  []string{keys.SigningAlgorithm},
	// SubjectTypesSupported:             []string{"public"},
	// TokenEndpointAuthMethodsSupported:
}

type endpoints struct {
	Authorization      Endpoint
	Token              Endpoint
	Introspection      Endpoint
	Userinfo           Endpoint
	EndSession         Endpoint
	CheckSessionIframe Endpoint
	JwksURI            Endpoint
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

func WithCustomEndSessionEndpoint(endpoint Endpoint) DefaultOPOpts {
	return func(o *DefaultOP) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.EndSession = endpoint
		return nil
	}
}

func WithCustomKeysEndpoint(endpoint Endpoint) DefaultOPOpts {
	return func(o *DefaultOP) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.JwksURI = endpoint
		return nil
	}
}

func WithHttpInterceptors(interceptors ...HttpInterceptor) DefaultOPOpts {
	return func(o *DefaultOP) error {
		o.interceptors = append(o.interceptors, interceptors...)
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

func WithTimer(timer <-chan time.Time) DefaultOPOpts {
	return func(o *DefaultOP) error {
		o.timer = timer
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
		timer:     make(<-chan time.Time),
	}

	for _, optFunc := range opOpts {
		if err := optFunc(p); err != nil {
			return nil, err
		}
	}

	keyCh := make(chan jose.SigningKey)
	p.signer = NewDefaultSigner(ctx, storage, keyCh)
	go p.ensureKey(ctx, storage, keyCh, p.timer)

	p.verifier = NewIDTokenHintVerifier(config.Issuer, p)

	p.http = CreateRouter(p, p.interceptors...)

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

func (p *DefaultOP) EndSessionEndpoint() Endpoint {
	return Endpoint(p.endpoints.EndSession)
}

func (p *DefaultOP) KeysEndpoint() Endpoint {
	return Endpoint(p.endpoints.JwksURI)
}

func (p *DefaultOP) AuthMethodPostSupported() bool {
	return true //TODO: config
}

func (p *DefaultOP) CodeMethodS256Supported() bool {
	return p.config.CodeMethodS256
}

func (p *DefaultOP) HttpHandler() http.Handler {
	return p.http
}

func (p *DefaultOP) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	Discover(w, CreateDiscoveryConfig(p, p.Signer()))
}

func (p *DefaultOP) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}
	keySet, err := p.Storage().GetKeySet(ctx)
	if err != nil {
		return nil, errors.New("error fetching keys")
	}
	payload, err, ok := rp.CheckKey(keyID, keySet.Keys, jws)
	if !ok {
		return nil, errors.New("invalid kid")
	}
	return payload, err
}

func (p *DefaultOP) Decoder() utils.Decoder {
	return p.decoder
}

func (p *DefaultOP) Encoder() utils.Encoder {
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

func (p *DefaultOP) ClientJWTVerifier() oidc.Verifier {
	return p.verifier
}

func (p *DefaultOP) Probes() []ProbesFn {
	return []ProbesFn{
		ReadySigner(p.Signer()),
		ReadyStorage(p.Storage()),
	}
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
		RequestError(w, r, ErrInvalidRequest("grant_type missing"))
		return
	}
	switch reqType {
	case string(oidc.GrantTypeCode):
		CodeExchange(w, r, p)
		return
	case string(oidc.GrantTypeBearer):
		JWTExchange(w, r, p)
		return
	}
	TokenExchange(w, r, p)
}

func (p *DefaultOP) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	Userinfo(w, r, p)
}

func (p *DefaultOP) HandleEndSession(w http.ResponseWriter, r *http.Request) {
	EndSession(w, r, p)
}

func (p *DefaultOP) DefaultLogoutRedirectURI() string {
	return p.config.DefaultLogoutRedirectURI
}
func (p *DefaultOP) IDTokenVerifier() IDTokenHintVerifier {
	return p.verifier
}

func (p *DefaultOP) ensureKey(ctx context.Context, storage Storage, keyCh chan<- jose.SigningKey, timer <-chan time.Time) {
	count := 0
	timer = time.After(0)
	errCh := make(chan error)
	go storage.GetSigningKey(ctx, keyCh, errCh, timer)
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
				timer = time.After(0)
				continue
			}
			logging.Log("OP-n6ynVE").WithError(err).Panic("error in key signer")
		}
	}
}

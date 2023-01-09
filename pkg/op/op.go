package op

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/rs/cors"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

const (
	healthEndpoint               = "/healthz"
	readinessEndpoint            = "/ready"
	authCallbackPathSuffix       = "/callback"
	defaultAuthorizationEndpoint = "authorize"
	defaultTokenEndpoint         = "oauth/token"
	defaultIntrospectEndpoint    = "oauth/introspect"
	defaultUserinfoEndpoint      = "userinfo"
	defaultRevocationEndpoint    = "revoke"
	defaultEndSessionEndpoint    = "end_session"
	defaultKeysEndpoint          = "keys"
)

var (
	DefaultEndpoints = &endpoints{
		Authorization: NewEndpoint(defaultAuthorizationEndpoint),
		Token:         NewEndpoint(defaultTokenEndpoint),
		Introspection: NewEndpoint(defaultIntrospectEndpoint),
		Userinfo:      NewEndpoint(defaultUserinfoEndpoint),
		Revocation:    NewEndpoint(defaultRevocationEndpoint),
		EndSession:    NewEndpoint(defaultEndSessionEndpoint),
		JwksURI:       NewEndpoint(defaultKeysEndpoint),
	}

	defaultCORSOptions = cors.Options{
		AllowCredentials: true,
		AllowedHeaders: []string{
			"Origin",
			"Accept",
			"Accept-Language",
			"Authorization",
			"Content-Type",
			"X-Requested-With",
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPost,
		},
		ExposedHeaders: []string{
			"Location",
			"Content-Length",
		},
		AllowOriginFunc: func(_ string) bool {
			return true
		},
	}
)

type OpenIDProvider interface {
	Configuration
	Storage() Storage
	Decoder() httphelper.Decoder
	Encoder() httphelper.Encoder
	IDTokenHintVerifier(context.Context) IDTokenHintVerifier
	AccessTokenVerifier(context.Context) AccessTokenVerifier
	Crypto() Crypto
	DefaultLogoutRedirectURI() string
	Probes() []ProbesFn
	HttpHandler() http.Handler
}

type HttpInterceptor func(http.Handler) http.Handler

func CreateRouter(o OpenIDProvider, interceptors ...HttpInterceptor) *mux.Router {
	router := mux.NewRouter()
	router.Use(intercept(o.IssuerFromRequest, interceptors...))
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readyHandler(o.Probes()))
	router.HandleFunc(oidc.DiscoveryEndpoint, discoveryHandler(o, o.Storage()))
	router.HandleFunc(o.AuthorizationEndpoint().Relative(), authorizeHandler(o))
	router.NewRoute().Path(authCallbackPath(o)).Queries("id", "{id}").HandlerFunc(authorizeCallbackHandler(o))
	router.HandleFunc(o.TokenEndpoint().Relative(), tokenHandler(o))
	router.HandleFunc(o.IntrospectionEndpoint().Relative(), introspectionHandler(o))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), userinfoHandler(o))
	router.HandleFunc(o.RevocationEndpoint().Relative(), revocationHandler(o))
	router.HandleFunc(o.EndSessionEndpoint().Relative(), endSessionHandler(o))
	router.HandleFunc(o.KeysEndpoint().Relative(), keysHandler(o.Storage()))
	return router
}

//AuthCallbackURL builds the url for the redirect (with the requestID) after a successful login
func AuthCallbackURL(o OpenIDProvider) func(context.Context, string) string {
	return func(ctx context.Context, requestID string) string {
		return o.AuthorizationEndpoint().Absolute(IssuerFromContext(ctx)) + authCallbackPathSuffix + "?id=" + requestID
	}
}

func authCallbackPath(o OpenIDProvider) string {
	return o.AuthorizationEndpoint().Relative() + authCallbackPathSuffix
}

type Config struct {
	CryptoKey                [32]byte
	DefaultLogoutRedirectURI string
	CodeMethodS256           bool
	AuthMethodPost           bool
	AuthMethodPrivateKeyJWT  bool
	GrantTypeRefreshToken    bool
	RequestObjectSupported   bool
	SupportedUILocales       []language.Tag
}

type endpoints struct {
	Authorization      Endpoint
	Token              Endpoint
	Introspection      Endpoint
	Userinfo           Endpoint
	Revocation         Endpoint
	EndSession         Endpoint
	CheckSessionIframe Endpoint
	JwksURI            Endpoint
}

func NewOpenIDProvider(ctx context.Context, issuer string, config *Config, storage Storage, opOpts ...Option) (*Provider, error) {
	return newProvider(ctx, config, storage, StaticIssuer(issuer), opOpts...)
}

func NewDynamicOpenIDProvider(ctx context.Context, path string, config *Config, storage Storage, opOpts ...Option) (*Provider, error) {
	return newProvider(ctx, config, storage, IssuerFromHost(path), opOpts...)
}

func newProvider(ctx context.Context, config *Config, storage Storage, issuer func(bool) (IssuerFromRequest, error), opOpts ...Option) (_ *Provider, err error) {
	o := &Provider{
		config:    config,
		storage:   storage,
		endpoints: DefaultEndpoints,
		timer:     make(<-chan time.Time),
	}

	for _, optFunc := range opOpts {
		if err := optFunc(o); err != nil {
			return nil, err
		}
	}

	o.issuer, err = issuer(o.insecure)
	if err != nil {
		return nil, err
	}

	o.httpHandler = CreateRouter(o, o.interceptors...)

	o.decoder = schema.NewDecoder()
	o.decoder.IgnoreUnknownKeys(true)

	o.encoder = schema.NewEncoder()

	o.crypto = NewAESCrypto(config.CryptoKey)

	return o, nil
}

type Provider struct {
	config       *Config
	issuer       IssuerFromRequest
	insecure     bool
	endpoints    *endpoints
	storage      Storage
	keySet       *openIDKeySet
	crypto       Crypto
	httpHandler  http.Handler
	decoder      *schema.Decoder
	encoder      *schema.Encoder
	interceptors []HttpInterceptor
	timer        <-chan time.Time
}

func (o *Provider) IssuerFromRequest(r *http.Request) string {
	return o.issuer(r)
}

func (o *Provider) Insecure() bool {
	return o.insecure
}

func (o *Provider) AuthorizationEndpoint() Endpoint {
	return o.endpoints.Authorization
}

func (o *Provider) TokenEndpoint() Endpoint {
	return o.endpoints.Token
}

func (o *Provider) IntrospectionEndpoint() Endpoint {
	return o.endpoints.Introspection
}

func (o *Provider) UserinfoEndpoint() Endpoint {
	return o.endpoints.Userinfo
}

func (o *Provider) RevocationEndpoint() Endpoint {
	return o.endpoints.Revocation
}

func (o *Provider) EndSessionEndpoint() Endpoint {
	return o.endpoints.EndSession
}

func (o *Provider) KeysEndpoint() Endpoint {
	return o.endpoints.JwksURI
}

func (o *Provider) AuthMethodPostSupported() bool {
	return o.config.AuthMethodPost
}

func (o *Provider) CodeMethodS256Supported() bool {
	return o.config.CodeMethodS256
}

func (o *Provider) AuthMethodPrivateKeyJWTSupported() bool {
	return o.config.AuthMethodPrivateKeyJWT
}

func (o *Provider) TokenEndpointSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *Provider) GrantTypeRefreshTokenSupported() bool {
	return o.config.GrantTypeRefreshToken
}

func (o *Provider) GrantTypeTokenExchangeSupported() bool {
	return false
}

func (o *Provider) GrantTypeJWTAuthorizationSupported() bool {
	return true
}

func (o *Provider) IntrospectionAuthMethodPrivateKeyJWTSupported() bool {
	return true
}

func (o *Provider) IntrospectionEndpointSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *Provider) RevocationAuthMethodPrivateKeyJWTSupported() bool {
	return true
}

func (o *Provider) RevocationEndpointSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *Provider) RequestObjectSupported() bool {
	return o.config.RequestObjectSupported
}

func (o *Provider) RequestObjectSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *Provider) SupportedUILocales() []language.Tag {
	return o.config.SupportedUILocales
}

func (o *Provider) Storage() Storage {
	return o.storage
}

func (o *Provider) Decoder() httphelper.Decoder {
	return o.decoder
}

func (o *Provider) Encoder() httphelper.Encoder {
	return o.encoder
}

func (o *Provider) IDTokenHintVerifier(ctx context.Context) IDTokenHintVerifier {
	return NewIDTokenHintVerifier(IssuerFromContext(ctx), o.openIDKeySet())
}

func (o *Provider) JWTProfileVerifier(ctx context.Context) JWTProfileVerifier {
	return NewJWTProfileVerifier(o.Storage(), IssuerFromContext(ctx), 1*time.Hour, time.Second)
}

func (o *Provider) AccessTokenVerifier(ctx context.Context) AccessTokenVerifier {
	return NewAccessTokenVerifier(IssuerFromContext(ctx), o.openIDKeySet())
}

func (o *Provider) openIDKeySet() oidc.KeySet {
	if o.keySet == nil {
		o.keySet = &openIDKeySet{o.Storage()}
	}
	return o.keySet
}

func (o *Provider) Crypto() Crypto {
	return o.crypto
}

func (o *Provider) DefaultLogoutRedirectURI() string {
	return o.config.DefaultLogoutRedirectURI
}

func (o *Provider) Probes() []ProbesFn {
	return []ProbesFn{
		ReadyStorage(o.Storage()),
	}
}

func (o *Provider) HttpHandler() http.Handler {
	return o.httpHandler
}

type openIDKeySet struct {
	Storage
}

//VerifySignature implements the oidc.KeySet interface
//providing an implementation for the keys stored in the OP Storage interface
func (o *openIDKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keySet, err := o.Storage.KeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, jsonWebKeySet(keySet).Keys...)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return jws.Verify(&key)
}

type Option func(o *Provider) error

//WithAllowInsecure allows the use of http (instead of https) for issuers
//this is not recommended for production use and violates the OIDC specification
func WithAllowInsecure() Option {
	return func(o *Provider) error {
		o.insecure = true
		return nil
	}
}

func WithCustomAuthEndpoint(endpoint Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Authorization = endpoint
		return nil
	}
}

func WithCustomTokenEndpoint(endpoint Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Token = endpoint
		return nil
	}
}

func WithCustomIntrospectionEndpoint(endpoint Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Introspection = endpoint
		return nil
	}
}

func WithCustomUserinfoEndpoint(endpoint Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Userinfo = endpoint
		return nil
	}
}

func WithCustomRevocationEndpoint(endpoint Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Revocation = endpoint
		return nil
	}
}

func WithCustomEndSessionEndpoint(endpoint Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.EndSession = endpoint
		return nil
	}
}

func WithCustomKeysEndpoint(endpoint Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.JwksURI = endpoint
		return nil
	}
}

func WithCustomEndpoints(auth, token, userInfo, revocation, endSession, keys Endpoint) Option {
	return func(o *Provider) error {
		o.endpoints.Authorization = auth
		o.endpoints.Token = token
		o.endpoints.Userinfo = userInfo
		o.endpoints.Revocation = revocation
		o.endpoints.EndSession = endSession
		o.endpoints.JwksURI = keys
		return nil
	}
}

func WithHttpInterceptors(interceptors ...HttpInterceptor) Option {
	return func(o *Provider) error {
		o.interceptors = append(o.interceptors, interceptors...)
		return nil
	}
}

func intercept(i IssuerFromRequest, interceptors ...HttpInterceptor) func(handler http.Handler) http.Handler {
	issuerInterceptor := NewIssuerInterceptor(i)
	return func(handler http.Handler) http.Handler {
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return cors.New(defaultCORSOptions).Handler(issuerInterceptor.Handler(handler))
	}
}

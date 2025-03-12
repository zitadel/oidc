package op

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/rs/cors"
	"github.com/zitadel/schema"
	"go.opentelemetry.io/otel"
	"golang.org/x/text/language"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
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
	defaultDeviceAuthzEndpoint   = "/device_authorization"
)

var (
	DefaultEndpoints = &Endpoints{
		Authorization:       NewEndpoint(defaultAuthorizationEndpoint),
		Token:               NewEndpoint(defaultTokenEndpoint),
		Introspection:       NewEndpoint(defaultIntrospectEndpoint),
		Userinfo:            NewEndpoint(defaultUserinfoEndpoint),
		Revocation:          NewEndpoint(defaultRevocationEndpoint),
		EndSession:          NewEndpoint(defaultEndSessionEndpoint),
		JwksURI:             NewEndpoint(defaultKeysEndpoint),
		DeviceAuthorization: NewEndpoint(defaultDeviceAuthzEndpoint),
	}

	DefaultSupportedClaims = []string{
		"sub",
		"aud",
		"exp",
		"iat",
		"iss",
		"auth_time",
		"nonce",
		"acr",
		"amr",
		"c_hash",
		"at_hash",
		"act",
		"scopes",
		"client_id",
		"azp",
		"preferred_username",
		"name",
		"family_name",
		"given_name",
		"locale",
		"email",
		"email_verified",
		"phone_number",
		"phone_number_verified",
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

var tracer = otel.Tracer("github.com/zitadel/oidc/pkg/op")

type OpenIDProvider interface {
	http.Handler
	Configuration
	Storage() Storage
	Decoder() httphelper.Decoder
	Encoder() httphelper.Encoder
	IDTokenHintVerifier(context.Context) *IDTokenHintVerifier
	AccessTokenVerifier(context.Context) *AccessTokenVerifier
	Crypto() Crypto
	DefaultLogoutRedirectURI() string
	Probes() []ProbesFn
	Logger() *slog.Logger

	// Deprecated: Provider now implements http.Handler directly.
	HttpHandler() http.Handler
}

type HttpInterceptor func(http.Handler) http.Handler

type corsOptioner interface {
	CORSOptions() *cors.Options
}

func CreateRouter(o OpenIDProvider, interceptors ...HttpInterceptor) chi.Router {
	router := chi.NewRouter()
	if co, ok := o.(corsOptioner); ok {
		if opts := co.CORSOptions(); opts != nil {
			router.Use(cors.New(*opts).Handler)
		}
	} else {
		router.Use(cors.New(defaultCORSOptions).Handler)
	}
	router.Use(intercept(o.IssuerFromRequest, interceptors...))
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readyHandler(o.Probes()))
	router.HandleFunc(oidc.DiscoveryEndpoint, discoveryHandler(o, o.Storage()))
	router.HandleFunc(o.AuthorizationEndpoint().Relative(), authorizeHandler(o))
	router.HandleFunc(authCallbackPath(o), AuthorizeCallbackHandler(o))
	router.HandleFunc(o.TokenEndpoint().Relative(), tokenHandler(o))
	router.HandleFunc(o.IntrospectionEndpoint().Relative(), introspectionHandler(o))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), userinfoHandler(o))
	router.HandleFunc(o.RevocationEndpoint().Relative(), revocationHandler(o))
	router.HandleFunc(o.EndSessionEndpoint().Relative(), endSessionHandler(o))
	router.HandleFunc(o.KeysEndpoint().Relative(), keysHandler(o.Storage()))
	router.HandleFunc(o.DeviceAuthorizationEndpoint().Relative(), DeviceAuthorizationHandler(o))
	return router
}

// AuthCallbackURL builds the url for the redirect (with the requestID) after a successful login
func AuthCallbackURL(o OpenIDProvider) func(context.Context, string) string {
	return func(ctx context.Context, requestID string) string {
		return o.AuthorizationEndpoint().Absolute(IssuerFromContext(ctx)) + authCallbackPathSuffix + "?id=" + requestID
	}
}

func authCallbackPath(o OpenIDProvider) string {
	return o.AuthorizationEndpoint().Relative() + authCallbackPathSuffix
}

type Config struct {
	CryptoKey                         [32]byte
	DefaultLogoutRedirectURI          string
	CodeMethodS256                    bool
	AuthMethodPost                    bool
	AuthMethodPrivateKeyJWT           bool
	GrantTypeRefreshToken             bool
	RequestObjectSupported            bool
	SupportedUILocales                []language.Tag
	SupportedClaims                   []string
	SupportedScopes                   []string
	DeviceAuthorization               DeviceAuthorizationConfig
	BackChannelLogoutSupported        bool
	BackChannelLogoutSessionSupported bool
}

// Endpoints defines endpoint routes.
type Endpoints struct {
	Authorization       *Endpoint
	Token               *Endpoint
	Introspection       *Endpoint
	Userinfo            *Endpoint
	Revocation          *Endpoint
	EndSession          *Endpoint
	CheckSessionIframe  *Endpoint
	JwksURI             *Endpoint
	DeviceAuthorization *Endpoint
}

// NewOpenIDProvider creates a provider. The provider provides (with HttpHandler())
// a http.Router that handles a suite of endpoints (some paths can be overridden):
//
//	/healthz
//	/ready
//	/.well-known/openid-configuration
//	/oauth/token
//	/oauth/introspect
//	/callback
//	/authorize
//	/userinfo
//	/revoke
//	/end_session
//	/keys
//	/device_authorization
//
// This does not include login. Login is handled with a redirect that includes the
// request ID. The redirect for logins is specified per-client by Client.LoginURL().
// Successful logins should mark the request as authorized and redirect back to to
// op.AuthCallbackURL(provider) which is probably /callback. On the redirect back
// to the AuthCallbackURL, the request id should be passed as the "id" parameter.
//
// Deprecated: use [NewProvider] with an issuer function direct.
func NewOpenIDProvider(issuer string, config *Config, storage Storage, opOpts ...Option) (*Provider, error) {
	return NewProvider(config, storage, StaticIssuer(issuer), opOpts...)
}

// NewForwardedOpenIDProvider tries to establishes the issuer from the request Host.
//
// Deprecated: use [NewProvider] with an issuer function direct.
func NewDynamicOpenIDProvider(path string, config *Config, storage Storage, opOpts ...Option) (*Provider, error) {
	return NewProvider(config, storage, IssuerFromHost(path), opOpts...)
}

// NewForwardedOpenIDProvider tries to establish the Issuer from a Forwarded request header, if it is set.
// See [IssuerFromForwardedOrHost] for details.
//
// Deprecated: use [NewProvider] with an issuer function direct.
func NewForwardedOpenIDProvider(path string, config *Config, storage Storage, opOpts ...Option) (*Provider, error) {
	return NewProvider(config, storage, IssuerFromForwardedOrHost(path), opOpts...)
}

// NewProvider creates a provider with a router on it's embedded http.Handler.
// Issuer is a function that must return the issuer on every request.
// Typically [StaticIssuer], [IssuerFromHost] or [IssuerFromForwardedOrHost] can be used.
//
// The router handles a suite of endpoints (some paths can be overridden):
//
//	/healthz
//	/ready
//	/.well-known/openid-configuration
//	/oauth/token
//	/oauth/introspect
//	/callback
//	/authorize
//	/userinfo
//	/revoke
//	/end_session
//	/keys
//	/device_authorization
//
// This does not include login. Login is handled with a redirect that includes the
// request ID. The redirect for logins is specified per-client by Client.LoginURL().
// Successful logins should mark the request as authorized and redirect back to to
// op.AuthCallbackURL(provider) which is probably /callback. On the redirect back
// to the AuthCallbackURL, the request id should be passed as the "id" parameter.
func NewProvider(config *Config, storage Storage, issuer func(insecure bool) (IssuerFromRequest, error), opOpts ...Option) (_ *Provider, err error) {
	keySet := &OpenIDKeySet{storage}
	o := &Provider{
		config:            config,
		storage:           storage,
		accessTokenKeySet: keySet,
		idTokenHinKeySet:  keySet,
		endpoints:         DefaultEndpoints,
		timer:             make(<-chan time.Time),
		corsOpts:          &defaultCORSOptions,
		logger:            slog.Default(),
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
	o.Handler = CreateRouter(o, o.interceptors...)
	o.decoder = schema.NewDecoder()
	o.decoder.IgnoreUnknownKeys(true)
	o.encoder = oidc.NewEncoder()
	o.crypto = NewAESCrypto(config.CryptoKey)
	return o, nil
}

type Provider struct {
	http.Handler
	config                  *Config
	issuer                  IssuerFromRequest
	insecure                bool
	endpoints               *Endpoints
	storage                 Storage
	accessTokenKeySet       oidc.KeySet
	idTokenHinKeySet        oidc.KeySet
	crypto                  Crypto
	decoder                 *schema.Decoder
	encoder                 *schema.Encoder
	interceptors            []HttpInterceptor
	timer                   <-chan time.Time
	accessTokenVerifierOpts []AccessTokenVerifierOpt
	idTokenHintVerifierOpts []IDTokenHintVerifierOpt
	corsOpts                *cors.Options
	logger                  *slog.Logger
}

func (o *Provider) IssuerFromRequest(r *http.Request) string {
	return o.issuer(r)
}

func (o *Provider) Insecure() bool {
	return o.insecure
}

func (o *Provider) AuthorizationEndpoint() *Endpoint {
	return o.endpoints.Authorization
}

func (o *Provider) TokenEndpoint() *Endpoint {
	return o.endpoints.Token
}

func (o *Provider) IntrospectionEndpoint() *Endpoint {
	return o.endpoints.Introspection
}

func (o *Provider) UserinfoEndpoint() *Endpoint {
	return o.endpoints.Userinfo
}

func (o *Provider) RevocationEndpoint() *Endpoint {
	return o.endpoints.Revocation
}

func (o *Provider) EndSessionEndpoint() *Endpoint {
	return o.endpoints.EndSession
}

func (o *Provider) DeviceAuthorizationEndpoint() *Endpoint {
	return o.endpoints.DeviceAuthorization
}

func (o *Provider) CheckSessionIframe() *Endpoint {
	return o.endpoints.CheckSessionIframe
}

func (o *Provider) KeysEndpoint() *Endpoint {
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
	_, ok := o.storage.(TokenExchangeStorage)
	return ok
}

func (o *Provider) GrantTypeJWTAuthorizationSupported() bool {
	return true
}

func (o *Provider) GrantTypeDeviceCodeSupported() bool {
	_, ok := o.storage.(DeviceAuthorizationStorage)
	return ok
}

func (o *Provider) IntrospectionAuthMethodPrivateKeyJWTSupported() bool {
	return true
}

func (o *Provider) IntrospectionEndpointSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *Provider) GrantTypeClientCredentialsSupported() bool {
	_, ok := o.storage.(ClientCredentialsStorage)
	return ok
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

func (o *Provider) DeviceAuthorization() DeviceAuthorizationConfig {
	return o.config.DeviceAuthorization
}

func (o *Provider) BackChannelLogoutSupported() bool {
	return o.config.BackChannelLogoutSupported
}

func (o *Provider) BackChannelLogoutSessionSupported() bool {
	return o.config.BackChannelLogoutSessionSupported
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

func (o *Provider) IDTokenHintVerifier(ctx context.Context) *IDTokenHintVerifier {
	return NewIDTokenHintVerifier(IssuerFromContext(ctx), o.idTokenHinKeySet, o.idTokenHintVerifierOpts...)
}

func (o *Provider) JWTProfileVerifier(ctx context.Context) *JWTProfileVerifier {
	return NewJWTProfileVerifier(o.Storage(), IssuerFromContext(ctx), 1*time.Hour, time.Second)
}

func (o *Provider) AccessTokenVerifier(ctx context.Context) *AccessTokenVerifier {
	return NewAccessTokenVerifier(IssuerFromContext(ctx), o.accessTokenKeySet, o.accessTokenVerifierOpts...)
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

func (o *Provider) CORSOptions() *cors.Options {
	return o.corsOpts
}

func (o *Provider) Logger() *slog.Logger {
	return o.logger
}

// Deprecated: Provider now implements http.Handler directly.
func (o *Provider) HttpHandler() http.Handler {
	return o
}

type OpenIDKeySet struct {
	Storage
}

// VerifySignature implements the oidc.KeySet interface
// providing an implementation for the keys stored in the OP Storage interface
func (o *OpenIDKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
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

// WithAllowInsecure allows the use of http (instead of https) for issuers
// this is not recommended for production use and violates the OIDC specification
func WithAllowInsecure() Option {
	return func(o *Provider) error {
		o.insecure = true
		return nil
	}
}

func WithCustomAuthEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Authorization = endpoint
		return nil
	}
}

func WithCustomTokenEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Token = endpoint
		return nil
	}
}

func WithCustomIntrospectionEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Introspection = endpoint
		return nil
	}
}

func WithCustomUserinfoEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Userinfo = endpoint
		return nil
	}
}

func WithCustomRevocationEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Revocation = endpoint
		return nil
	}
}

func WithCustomEndSessionEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.EndSession = endpoint
		return nil
	}
}

func WithCustomKeysEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.JwksURI = endpoint
		return nil
	}
}

func WithCustomDeviceAuthorizationEndpoint(endpoint *Endpoint) Option {
	return func(o *Provider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.DeviceAuthorization = endpoint
		return nil
	}
}

// WithCustomEndpoints sets multiple endpoints at once.
// Non of the endpoints may be nil, or an error will
// be returned when the Option used by the Provider.
func WithCustomEndpoints(auth, token, userInfo, revocation, endSession, keys *Endpoint) Option {
	return func(o *Provider) error {
		for _, e := range []*Endpoint{auth, token, userInfo, revocation, endSession, keys} {
			if err := e.Validate(); err != nil {
				return err
			}
		}
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

// WithAccessTokenKeySet allows passing a KeySet with public keys for Access Token verification.
// The default KeySet uses the [Storage] interface
func WithAccessTokenKeySet(keySet oidc.KeySet) Option {
	return func(o *Provider) error {
		o.accessTokenKeySet = keySet
		return nil
	}
}

func WithAccessTokenVerifierOpts(opts ...AccessTokenVerifierOpt) Option {
	return func(o *Provider) error {
		o.accessTokenVerifierOpts = opts
		return nil
	}
}

// WithIDTokenHintKeySet allows passing a KeySet with public keys for ID Token Hint verification.
// The default KeySet uses the [Storage] interface.
func WithIDTokenHintKeySet(keySet oidc.KeySet) Option {
	return func(o *Provider) error {
		o.idTokenHinKeySet = keySet
		return nil
	}
}

func WithIDTokenHintVerifierOpts(opts ...IDTokenHintVerifierOpt) Option {
	return func(o *Provider) error {
		o.idTokenHintVerifierOpts = opts
		return nil
	}
}

func WithCORSOptions(opts *cors.Options) Option {
	return func(o *Provider) error {
		o.corsOpts = opts
		return nil
	}
}

// WithLogger lets a logger other than slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(o *Provider) error {
		o.logger = logger
		return nil
	}
}

func intercept(i IssuerFromRequest, interceptors ...HttpInterceptor) func(handler http.Handler) http.Handler {
	issuerInterceptor := NewIssuerInterceptor(i)
	return func(handler http.Handler) http.Handler {
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return issuerInterceptor.Handler(handler)
	}
}

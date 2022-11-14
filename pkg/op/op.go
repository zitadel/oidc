package op

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"

	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
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

var DefaultEndpoints = &endpoints{
	Authorization: NewEndpoint(defaultAuthorizationEndpoint),
	Token:         NewEndpoint(defaultTokenEndpoint),
	Introspection: NewEndpoint(defaultIntrospectEndpoint),
	Userinfo:      NewEndpoint(defaultUserinfoEndpoint),
	Revocation:    NewEndpoint(defaultRevocationEndpoint),
	EndSession:    NewEndpoint(defaultEndSessionEndpoint),
	JwksURI:       NewEndpoint(defaultKeysEndpoint),
}

type OpenIDProvider interface {
	Configuration
	Storage() Storage
	Decoder() httphelper.Decoder
	Encoder() httphelper.Encoder
	IDTokenHintVerifier() IDTokenHintVerifier
	AccessTokenVerifier() AccessTokenVerifier
	Crypto() Crypto
	DefaultLogoutRedirectURI() string
	Signer() Signer
	Probes() []ProbesFn
	HttpHandler() http.Handler
}

type HttpInterceptor func(http.Handler) http.Handler

var allowAllOrigins = func(_ string) bool {
	return true
}

func CreateRouter(o OpenIDProvider, interceptors ...HttpInterceptor) *mux.Router {
	intercept := buildInterceptor(interceptors...)
	router := mux.NewRouter()
	router.Use(handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedHeaders([]string{"authorization", "content-type"}),
		handlers.AllowedOriginValidator(allowAllOrigins),
	))
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readyHandler(o.Probes()))
	router.HandleFunc(oidc.DiscoveryEndpoint, discoveryHandler(o, o.Signer()))
	router.Handle(o.AuthorizationEndpoint().Relative(), intercept(authorizeHandler(o)))
	router.NewRoute().Path(authCallbackPath(o)).Queries("id", "{id}").Handler(intercept(authorizeCallbackHandler(o)))
	router.Handle(o.TokenEndpoint().Relative(), intercept(tokenHandler(o)))
	router.HandleFunc(o.IntrospectionEndpoint().Relative(), introspectionHandler(o))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), userinfoHandler(o))
	router.HandleFunc(o.RevocationEndpoint().Relative(), revocationHandler(o))
	router.Handle(o.EndSessionEndpoint().Relative(), intercept(endSessionHandler(o)))
	router.HandleFunc(o.KeysEndpoint().Relative(), keysHandler(o.Storage()))
	return router
}

// AuthCallbackURL builds the url for the redirect (with the requestID) after a successful login
func AuthCallbackURL(o OpenIDProvider) func(string) string {
	return func(requestID string) string {
		return o.AuthorizationEndpoint().Absolute(o.Issuer()) + authCallbackPathSuffix + "?id=" + requestID
	}
}

func authCallbackPath(o OpenIDProvider) string {
	return o.AuthorizationEndpoint().Relative() + authCallbackPathSuffix
}

type Config struct {
	Issuer                   string
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

// NewOpenIDProvider creates a provider. The provider provides (with HttpHandler())
// a http.Router that handles a suite of endpoints (some paths can be overridden):
//  /healthz
//  /ready
//  /.well-known/openid-configuration
//  /oauth/token
//  /oauth/introspect
//  /callback
//  /authorize
//  /userinfo
//  /revoke
//  /end_session
//  /keys
// This does not include login. Login is handled with a redirect that includes the
// request ID. The redirect for logins is specified per-client by Client.LoginURL().
// Successful logins should mark the request as authorized and redirect back to to
// op.AuthCallbackURL(provider) which is probably /callback. On the redirect back
// to the AuthCallbackURL, the request id should be passed as the "id" parameter.
func NewOpenIDProvider(ctx context.Context, config *Config, storage Storage, opOpts ...Option) (OpenIDProvider, error) {
	err := ValidateIssuer(config.Issuer)
	if err != nil {
		return nil, err
	}

	o := &openidProvider{
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

	keyCh := make(chan jose.SigningKey)
	go storage.GetSigningKey(ctx, keyCh)
	o.signer = NewSigner(ctx, storage, keyCh)

	o.httpHandler = CreateRouter(o, o.interceptors...)

	o.decoder = schema.NewDecoder()
	o.decoder.IgnoreUnknownKeys(true)

	o.encoder = schema.NewEncoder()

	o.crypto = NewAESCrypto(config.CryptoKey)

	// Avoid potential race conditions by calling these early
	_ = o.AccessTokenVerifier() // sets accessTokenVerifier
	_ = o.IDTokenHintVerifier() // sets idTokenHintVerifier
	_ = o.JWTProfileVerifier()  // sets jwtProfileVerifier
	_ = o.openIDKeySet()        // sets keySet

	return o, nil
}

type openidProvider struct {
	config                  *Config
	endpoints               *endpoints
	storage                 Storage
	signer                  Signer
	idTokenHintVerifier     IDTokenHintVerifier
	jwtProfileVerifier      JWTProfileVerifier
	accessTokenVerifier     AccessTokenVerifier
	keySet                  *openIDKeySet
	crypto                  Crypto
	httpHandler             http.Handler
	decoder                 *schema.Decoder
	encoder                 *schema.Encoder
	interceptors            []HttpInterceptor
	timer                   <-chan time.Time
	accessTokenVerifierOpts []AccessTokenVerifierOpt
	idTokenHintVerifierOpts     []IDTokenHintVerifierOpt
}

func (o *openidProvider) Issuer() string {
	return o.config.Issuer
}

func (o *openidProvider) AuthorizationEndpoint() Endpoint {
	return o.endpoints.Authorization
}

func (o *openidProvider) TokenEndpoint() Endpoint {
	return o.endpoints.Token
}

func (o *openidProvider) IntrospectionEndpoint() Endpoint {
	return o.endpoints.Introspection
}

func (o *openidProvider) UserinfoEndpoint() Endpoint {
	return o.endpoints.Userinfo
}

func (o *openidProvider) RevocationEndpoint() Endpoint {
	return o.endpoints.Revocation
}

func (o *openidProvider) EndSessionEndpoint() Endpoint {
	return o.endpoints.EndSession
}

func (o *openidProvider) KeysEndpoint() Endpoint {
	return o.endpoints.JwksURI
}

func (o *openidProvider) AuthMethodPostSupported() bool {
	return o.config.AuthMethodPost
}

func (o *openidProvider) CodeMethodS256Supported() bool {
	return o.config.CodeMethodS256
}

func (o *openidProvider) AuthMethodPrivateKeyJWTSupported() bool {
	return o.config.AuthMethodPrivateKeyJWT
}

func (o *openidProvider) TokenEndpointSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *openidProvider) GrantTypeRefreshTokenSupported() bool {
	return o.config.GrantTypeRefreshToken
}

func (o *openidProvider) GrantTypeTokenExchangeSupported() bool {
	return false
}

func (o *openidProvider) GrantTypeJWTAuthorizationSupported() bool {
	return true
}

func (o *openidProvider) GrantTypeClientCredentialsSupported() bool {
	_, ok := o.storage.(ClientCredentialsStorage)
	return ok
}

func (o *openidProvider) IntrospectionAuthMethodPrivateKeyJWTSupported() bool {
	return true
}

func (o *openidProvider) IntrospectionEndpointSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *openidProvider) RevocationAuthMethodPrivateKeyJWTSupported() bool {
	return true
}

func (o *openidProvider) RevocationEndpointSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *openidProvider) RequestObjectSupported() bool {
	return o.config.RequestObjectSupported
}

func (o *openidProvider) RequestObjectSigningAlgorithmsSupported() []string {
	return []string{"RS256"}
}

func (o *openidProvider) SupportedUILocales() []language.Tag {
	return o.config.SupportedUILocales
}

func (o *openidProvider) Storage() Storage {
	return o.storage
}

func (o *openidProvider) Decoder() httphelper.Decoder {
	return o.decoder
}

func (o *openidProvider) Encoder() httphelper.Encoder {
	return o.encoder
}

func (o *openidProvider) IDTokenHintVerifier() IDTokenHintVerifier {
	if o.idTokenHintVerifier == nil {
		o.idTokenHintVerifier = NewIDTokenHintVerifier(o.Issuer(), o.openIDKeySet(), o.idTokenHintVerifierOpts...)
	}
	return o.idTokenHintVerifier
}

func (o *openidProvider) JWTProfileVerifier() JWTProfileVerifier {
	if o.jwtProfileVerifier == nil {
		o.jwtProfileVerifier = NewJWTProfileVerifier(o.Storage(), o.Issuer(), 1*time.Hour, time.Second)
	}
	return o.jwtProfileVerifier
}

func (o *openidProvider) AccessTokenVerifier() AccessTokenVerifier {
	if o.accessTokenVerifier == nil {
		o.accessTokenVerifier = NewAccessTokenVerifier(o.Issuer(), o.openIDKeySet())
	}
	return o.accessTokenVerifier
}

func (o *openidProvider) openIDKeySet() oidc.KeySet {
	if o.keySet == nil {
		o.keySet = &openIDKeySet{o.Storage()}
	}
	return o.keySet
}

func (o *openidProvider) Crypto() Crypto {
	return o.crypto
}

func (o *openidProvider) DefaultLogoutRedirectURI() string {
	return o.config.DefaultLogoutRedirectURI
}

func (o *openidProvider) Signer() Signer {
	return o.signer
}

func (o *openidProvider) Probes() []ProbesFn {
	return []ProbesFn{
		ReadySigner(o.Signer()),
		ReadyStorage(o.Storage()),
	}
}

func (o *openidProvider) HttpHandler() http.Handler {
	return o.httpHandler
}

type openIDKeySet struct {
	Storage
}

// VerifySignature implements the oidc.KeySet interface
// providing an implementation for the keys stored in the OP Storage interface
func (o *openIDKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keySet, err := o.Storage.GetKeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, keySet.Keys...)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return jws.Verify(&key)
}

type Option func(o *openidProvider) error

func WithCustomAuthEndpoint(endpoint Endpoint) Option {
	return func(o *openidProvider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Authorization = endpoint
		return nil
	}
}

func WithCustomTokenEndpoint(endpoint Endpoint) Option {
	return func(o *openidProvider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Token = endpoint
		return nil
	}
}

func WithCustomIntrospectionEndpoint(endpoint Endpoint) Option {
	return func(o *openidProvider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Introspection = endpoint
		return nil
	}
}

func WithCustomUserinfoEndpoint(endpoint Endpoint) Option {
	return func(o *openidProvider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Userinfo = endpoint
		return nil
	}
}

func WithCustomRevocationEndpoint(endpoint Endpoint) Option {
	return func(o *openidProvider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.Revocation = endpoint
		return nil
	}
}

func WithCustomEndSessionEndpoint(endpoint Endpoint) Option {
	return func(o *openidProvider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.EndSession = endpoint
		return nil
	}
}

func WithCustomKeysEndpoint(endpoint Endpoint) Option {
	return func(o *openidProvider) error {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		o.endpoints.JwksURI = endpoint
		return nil
	}
}

func WithCustomEndpoints(auth, token, userInfo, revocation, endSession, keys Endpoint) Option {
	return func(o *openidProvider) error {
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
	return func(o *openidProvider) error {
		o.interceptors = append(o.interceptors, interceptors...)
		return nil
	}
}

func WithAccessTokenVerifierOpts(opts ...AccessTokenVerifierOpt) Option {
	return func(o *openidProvider) error {
		o.accessTokenVerifierOpts = opts
		return nil
	}
}

func WithIDTokenHintVerifierOpts(opts ...IDTokenHintVerifierOpt) Option {
	return func(o *openidProvider) error {
		o.idTokenHintVerifierOpts = opts
		return nil
	}
}

func buildInterceptor(interceptors ...HttpInterceptor) func(http.HandlerFunc) http.Handler {
	return func(handlerFunc http.HandlerFunc) http.Handler {
		handler := handlerFuncToHandler(handlerFunc)
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return handler
	}
}

func handlerFuncToHandler(handlerFunc http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerFunc(w, r)
	})
}

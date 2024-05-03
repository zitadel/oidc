package rp

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	idTokenKey = "id_token"
	stateParam = "state"
	pkceCode   = "pkce"
)

var ErrUserInfoSubNotMatching = errors.New("sub from userinfo does not match the sub from the id_token")

// RelyingParty declares the minimal interface for oidc clients
type RelyingParty interface {
	// OAuthConfig returns the oauth2 Config
	OAuthConfig() *oauth2.Config

	// Issuer returns the issuer of the oidc config
	Issuer() string

	// IsPKCE returns if authorization is done using `Authorization Code Flow with Proof Key for Code Exchange (PKCE)`
	IsPKCE() bool

	// CookieHandler returns a http cookie handler used for various state transfer cookies
	CookieHandler() *httphelper.CookieHandler

	// HttpClient returns a http client used for calls to the openid provider, e.g. calling token endpoint
	HttpClient() *http.Client

	// IsOAuth2Only specifies whether relaying party handles only oauth2 or oidc calls
	IsOAuth2Only() bool

	// Signer is used if the relaying party uses the JWT Profile
	Signer() jose.Signer

	// GetEndSessionEndpoint returns the endpoint to sign out on a IDP
	GetEndSessionEndpoint() string

	// GetRevokeEndpoint returns the endpoint to revoke a specific token
	GetRevokeEndpoint() string

	// UserinfoEndpoint returns the userinfo
	UserinfoEndpoint() string

	// GetDeviceAuthorizationEndpoint returns the endpoint which can
	// be used to start a DeviceAuthorization flow.
	GetDeviceAuthorizationEndpoint() string

	// IDTokenVerifier returns the verifier used for oidc id_token verification
	IDTokenVerifier() *IDTokenVerifier

	// ErrorHandler returns the handler used for callback errors
	ErrorHandler() func(http.ResponseWriter, *http.Request, string, string, string)

	// Logger from the context, or a fallback if set.
	Logger(context.Context) (logger *slog.Logger, ok bool)
}

type HasUnauthorizedHandler interface {
	// UnauthorizedHandler returns the handler used for unauthorized errors
	UnauthorizedHandler() func(w http.ResponseWriter, r *http.Request, desc string, state string)
}

type ErrorHandler func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, state string)
type UnauthorizedHandler func(w http.ResponseWriter, r *http.Request, desc string, state string)

var DefaultErrorHandler ErrorHandler = func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, state string) {
	http.Error(w, errorType+": "+errorDesc, http.StatusInternalServerError)
}
var DefaultUnauthorizedHandler UnauthorizedHandler = func(w http.ResponseWriter, r *http.Request, desc string, state string) {
	http.Error(w, desc, http.StatusUnauthorized)
}

type relyingParty struct {
	issuer                      string
	DiscoveryEndpoint           string
	endpoints                   Endpoints
	oauthConfig                 *oauth2.Config
	oauth2Only                  bool
	pkce                        bool
	useSigningAlgsFromDiscovery bool

	httpClient    *http.Client
	cookieHandler *httphelper.CookieHandler

	oauthAuthStyle oauth2.AuthStyle

	errorHandler        func(http.ResponseWriter, *http.Request, string, string, string)
	unauthorizedHandler func(http.ResponseWriter, *http.Request, string, string)
	idTokenVerifier     *IDTokenVerifier
	verifierOpts        []VerifierOption
	signer              jose.Signer
	logger              *slog.Logger
}

func (rp *relyingParty) OAuthConfig() *oauth2.Config {
	return rp.oauthConfig
}

func (rp *relyingParty) Issuer() string {
	return rp.issuer
}

func (rp *relyingParty) IsPKCE() bool {
	return rp.pkce
}

func (rp *relyingParty) CookieHandler() *httphelper.CookieHandler {
	return rp.cookieHandler
}

func (rp *relyingParty) HttpClient() *http.Client {
	return rp.httpClient
}

func (rp *relyingParty) IsOAuth2Only() bool {
	return rp.oauth2Only
}

func (rp *relyingParty) Signer() jose.Signer {
	return rp.signer
}

func (rp *relyingParty) UserinfoEndpoint() string {
	return rp.endpoints.UserinfoURL
}

func (rp *relyingParty) GetDeviceAuthorizationEndpoint() string {
	return rp.endpoints.DeviceAuthorizationURL
}

func (rp *relyingParty) GetEndSessionEndpoint() string {
	return rp.endpoints.EndSessionURL
}

func (rp *relyingParty) GetRevokeEndpoint() string {
	return rp.endpoints.RevokeURL
}

func (rp *relyingParty) IDTokenVerifier() *IDTokenVerifier {
	if rp.idTokenVerifier == nil {
		rp.idTokenVerifier = NewIDTokenVerifier(rp.issuer, rp.oauthConfig.ClientID, NewRemoteKeySet(rp.httpClient, rp.endpoints.JKWsURL), rp.verifierOpts...)
	}
	return rp.idTokenVerifier
}

func (rp *relyingParty) ErrorHandler() func(http.ResponseWriter, *http.Request, string, string, string) {
	if rp.errorHandler == nil {
		rp.errorHandler = DefaultErrorHandler
	}
	return rp.errorHandler
}

func (rp *relyingParty) UnauthorizedHandler() func(http.ResponseWriter, *http.Request, string, string) {
	if rp.unauthorizedHandler == nil {
		rp.unauthorizedHandler = DefaultUnauthorizedHandler
	}
	return rp.unauthorizedHandler
}

func (rp *relyingParty) Logger(ctx context.Context) (logger *slog.Logger, ok bool) {
	logger, ok = logging.FromContext(ctx)
	if ok {
		return logger, ok
	}
	return rp.logger, rp.logger != nil
}

// NewRelyingPartyOAuth creates an (OAuth2) RelyingParty with the given
// OAuth2 Config and possible configOptions
// it will use the AuthURL and TokenURL set in config
func NewRelyingPartyOAuth(config *oauth2.Config, options ...Option) (RelyingParty, error) {
	rp := &relyingParty{
		oauthConfig:         config,
		httpClient:          httphelper.DefaultHTTPClient,
		oauth2Only:          true,
		unauthorizedHandler: DefaultUnauthorizedHandler,
		oauthAuthStyle:      oauth2.AuthStyleAutoDetect,
	}

	for _, optFunc := range options {
		if err := optFunc(rp); err != nil {
			return nil, err
		}
	}

	rp.oauthConfig.Endpoint.AuthStyle = rp.oauthAuthStyle

	// avoid races by calling these early
	_ = rp.IDTokenVerifier()     // sets idTokenVerifier
	_ = rp.ErrorHandler()        // sets errorHandler
	_ = rp.UnauthorizedHandler() // sets unauthorizedHandler

	return rp, nil
}

// NewRelyingPartyOIDC creates an (OIDC) RelyingParty with the given
// issuer, clientID, clientSecret, redirectURI, scopes and possible configOptions
// it will run discovery on the provided issuer and use the found endpoints
func NewRelyingPartyOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURI string, scopes []string, options ...Option) (RelyingParty, error) {
	rp := &relyingParty{
		issuer: issuer,
		oauthConfig: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Scopes:       scopes,
		},
		httpClient:     httphelper.DefaultHTTPClient,
		oauth2Only:     false,
		oauthAuthStyle: oauth2.AuthStyleAutoDetect,
	}

	for _, optFunc := range options {
		if err := optFunc(rp); err != nil {
			return nil, err
		}
	}
	ctx = logCtxWithRPData(ctx, rp, "function", "NewRelyingPartyOIDC")
	discoveryConfiguration, err := client.Discover(ctx, rp.issuer, rp.httpClient, rp.DiscoveryEndpoint)
	if err != nil {
		return nil, err
	}
	if rp.useSigningAlgsFromDiscovery {
		rp.verifierOpts = append(rp.verifierOpts, WithSupportedSigningAlgorithms(discoveryConfiguration.IDTokenSigningAlgValuesSupported...))
	}
	endpoints := GetEndpoints(discoveryConfiguration)
	rp.oauthConfig.Endpoint = endpoints.Endpoint
	rp.endpoints = endpoints

	rp.oauthConfig.Endpoint.AuthStyle = rp.oauthAuthStyle
	rp.endpoints.Endpoint.AuthStyle = rp.oauthAuthStyle

	// avoid races by calling these early
	_ = rp.IDTokenVerifier()     // sets idTokenVerifier
	_ = rp.ErrorHandler()        // sets errorHandler
	_ = rp.UnauthorizedHandler() // sets unauthorizedHandler

	return rp, nil
}

// Option is the type for providing dynamic options to the relyingParty
type Option func(*relyingParty) error

func WithCustomDiscoveryUrl(url string) Option {
	return func(rp *relyingParty) error {
		rp.DiscoveryEndpoint = url
		return nil
	}
}

// WithCookieHandler set a `CookieHandler` for securing the various redirects
func WithCookieHandler(cookieHandler *httphelper.CookieHandler) Option {
	return func(rp *relyingParty) error {
		rp.cookieHandler = cookieHandler
		return nil
	}
}

// WithPKCE sets the RP to use PKCE (oauth2 code challenge)
// it also sets a `CookieHandler` for securing the various redirects
// and exchanging the code challenge
func WithPKCE(cookieHandler *httphelper.CookieHandler) Option {
	return func(rp *relyingParty) error {
		rp.pkce = true
		rp.cookieHandler = cookieHandler
		return nil
	}
}

// WithHTTPClient provides the ability to set an http client to be used for the relaying party and verifier
func WithHTTPClient(client *http.Client) Option {
	return func(rp *relyingParty) error {
		rp.httpClient = client
		return nil
	}
}

func WithErrorHandler(errorHandler ErrorHandler) Option {
	return func(rp *relyingParty) error {
		rp.errorHandler = errorHandler
		return nil
	}
}

func WithUnauthorizedHandler(unauthorizedHandler UnauthorizedHandler) Option {
	return func(rp *relyingParty) error {
		rp.unauthorizedHandler = unauthorizedHandler
		return nil
	}
}

func WithAuthStyle(oauthAuthStyle oauth2.AuthStyle) Option {
	return func(rp *relyingParty) error {
		rp.oauthAuthStyle = oauthAuthStyle
		return nil
	}
}

func WithVerifierOpts(opts ...VerifierOption) Option {
	return func(rp *relyingParty) error {
		rp.verifierOpts = opts
		return nil
	}
}

// WithClientKey specifies the path to the key.json to be used for the JWT Profile Client Authentication on the token endpoint
//
// deprecated: use WithJWTProfile(SignerFromKeyPath(path)) instead
func WithClientKey(path string) Option {
	return WithJWTProfile(SignerFromKeyPath(path))
}

// WithJWTProfile creates a signer used for the JWT Profile Client Authentication on the token endpoint
// When creating the signer, be sure to include the KeyID in the SigningKey.
// See client.NewSignerFromPrivateKeyByte for an example.
func WithJWTProfile(signerFromKey SignerFromKey) Option {
	return func(rp *relyingParty) error {
		signer, err := signerFromKey()
		if err != nil {
			return err
		}
		rp.signer = signer
		return nil
	}
}

// WithLogger sets a logger that is used
// in case the request context does not contain a logger.
func WithLogger(logger *slog.Logger) Option {
	return func(rp *relyingParty) error {
		rp.logger = logger
		return nil
	}
}

// WithSigningAlgsFromDiscovery appends the [WithSupportedSigningAlgorithms] option to the Verifier Options.
// The algorithms returned in the `id_token_signing_alg_values_supported` from the discovery response will be set.
func WithSigningAlgsFromDiscovery() Option {
	return func(rp *relyingParty) error {
		rp.useSigningAlgsFromDiscovery = true
		return nil
	}
}

type SignerFromKey func() (jose.Signer, error)

func SignerFromKeyPath(path string) SignerFromKey {
	return func() (jose.Signer, error) {
		config, err := client.ConfigFromKeyFile(path)
		if err != nil {
			return nil, err
		}
		return client.NewSignerFromPrivateKeyByte([]byte(config.Key), config.KeyID)
	}
}

func SignerFromKeyFile(fileData []byte) SignerFromKey {
	return func() (jose.Signer, error) {
		config, err := client.ConfigFromKeyFileData(fileData)
		if err != nil {
			return nil, err
		}
		return client.NewSignerFromPrivateKeyByte([]byte(config.Key), config.KeyID)
	}
}

func SignerFromKeyAndKeyID(key []byte, keyID string) SignerFromKey {
	return func() (jose.Signer, error) {
		return client.NewSignerFromPrivateKeyByte(key, keyID)
	}
}

// AuthURL returns the auth request url
// (wrapping the oauth2 `AuthCodeURL`)
func AuthURL(state string, rp RelyingParty, opts ...AuthURLOpt) string {
	authOpts := make([]oauth2.AuthCodeOption, 0)
	for _, opt := range opts {
		authOpts = append(authOpts, opt()...)
	}
	return rp.OAuthConfig().AuthCodeURL(state, authOpts...)
}

// AuthURLHandler extends the `AuthURL` method with a http redirect handler
// including handling setting cookie for secure `state` transfer.
// Custom parameters can optionally be set to the redirect URL.
func AuthURLHandler(stateFn func() string, rp RelyingParty, urlParam ...URLParamOpt) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts := make([]AuthURLOpt, len(urlParam))
		for i, p := range urlParam {
			opts[i] = AuthURLOpt(p)
		}

		state := stateFn()
		if err := trySetStateCookie(w, state, rp); err != nil {
			unauthorizedError(w, r, "failed to create state cookie: "+err.Error(), state, rp)
			return
		}
		if rp.IsPKCE() {
			codeChallenge, err := GenerateAndStoreCodeChallenge(w, rp)
			if err != nil {
				unauthorizedError(w, r, "failed to create code challenge: "+err.Error(), state, rp)
				return
			}
			opts = append(opts, WithCodeChallenge(codeChallenge))
		}

		http.Redirect(w, r, AuthURL(state, rp, opts...), http.StatusFound)
	}
}

// GenerateAndStoreCodeChallenge generates a PKCE code challenge and stores its verifier into a secure cookie
func GenerateAndStoreCodeChallenge(w http.ResponseWriter, rp RelyingParty) (string, error) {
	codeVerifier := base64.RawURLEncoding.EncodeToString([]byte(uuid.New().String()))
	if err := rp.CookieHandler().SetCookie(w, pkceCode, codeVerifier); err != nil {
		return "", err
	}
	return oidc.NewSHACodeChallenge(codeVerifier), nil
}

// ErrMissingIDToken is returned when an id_token was expected,
// but not received in the token response.
var ErrMissingIDToken = errors.New("id_token missing")

func verifyTokenResponse[C oidc.IDClaims](ctx context.Context, token *oauth2.Token, rp RelyingParty) (*oidc.Tokens[C], error) {
	ctx, span := client.Tracer.Start(ctx, "verifyTokenResponse")
	defer span.End()

	if rp.IsOAuth2Only() {
		return &oidc.Tokens[C]{Token: token}, nil
	}
	idTokenString, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return &oidc.Tokens[C]{Token: token}, ErrMissingIDToken
	}
	idToken, err := VerifyTokens[C](ctx, token.AccessToken, idTokenString, rp.IDTokenVerifier())
	if err != nil {
		return nil, err
	}
	return &oidc.Tokens[C]{Token: token, IDTokenClaims: idToken, IDToken: idTokenString}, nil
}

// CodeExchange handles the oauth2 code exchange, extracting and validating the id_token
// returning it parsed together with the oauth2 tokens (access, refresh)
func CodeExchange[C oidc.IDClaims](ctx context.Context, code string, rp RelyingParty, opts ...CodeExchangeOpt) (tokens *oidc.Tokens[C], err error) {
	ctx, codeExchangeSpan := client.Tracer.Start(ctx, "CodeExchange")
	defer codeExchangeSpan.End()

	ctx = logCtxWithRPData(ctx, rp, "function", "CodeExchange")
	ctx = context.WithValue(ctx, oauth2.HTTPClient, rp.HttpClient())
	codeOpts := make([]oauth2.AuthCodeOption, 0)
	for _, opt := range opts {
		codeOpts = append(codeOpts, opt()...)
	}

	ctx, oauthExchangeSpan := client.Tracer.Start(ctx, "OAuthExchange")
	token, err := rp.OAuthConfig().Exchange(ctx, code, codeOpts...)
	if err != nil {
		return nil, err
	}
	oauthExchangeSpan.End()
	return verifyTokenResponse[C](ctx, token, rp)
}

// ClientCredentials requests an access token using the `client_credentials` grant,
// as defined in [RFC 6749, section 4.4].
//
// As there is no user associated to the request an ID Token can never be returned.
// Client Credentials are undefined in OpenID Connect and is a pure OAuth2 grant.
// Furthermore the server SHOULD NOT return a refresh token.
//
// [RFC 6749, section 4.4]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
func ClientCredentials(ctx context.Context, rp RelyingParty, endpointParams url.Values) (token *oauth2.Token, err error) {
	ctx = logCtxWithRPData(ctx, rp, "function", "ClientCredentials")
	ctx, span := client.Tracer.Start(ctx, "ClientCredentials")
	defer span.End()

	ctx = context.WithValue(ctx, oauth2.HTTPClient, rp.HttpClient())
	config := clientcredentials.Config{
		ClientID:       rp.OAuthConfig().ClientID,
		ClientSecret:   rp.OAuthConfig().ClientSecret,
		TokenURL:       rp.OAuthConfig().Endpoint.TokenURL,
		Scopes:         rp.OAuthConfig().Scopes,
		EndpointParams: endpointParams,
		AuthStyle:      rp.OAuthConfig().Endpoint.AuthStyle,
	}
	return config.Token(ctx)
}

type CodeExchangeCallback[C oidc.IDClaims] func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], state string, rp RelyingParty)

// CodeExchangeHandler extends the `CodeExchange` method with a http handler
// including cookie handling for secure `state` transfer
// and optional PKCE code verifier checking.
// Custom parameters can optionally be set to the token URL.
func CodeExchangeHandler[C oidc.IDClaims](callback CodeExchangeCallback[C], rp RelyingParty, urlParam ...URLParamOpt) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := client.Tracer.Start(r.Context(), "CodeExchangeHandler")
		r = r.WithContext(ctx)
		defer span.End()

		state, err := tryReadStateCookie(w, r, rp)
		if err != nil {
			unauthorizedError(w, r, "failed to get state: "+err.Error(), state, rp)
			return
		}
		if errValue := r.FormValue("error"); errValue != "" {
			rp.ErrorHandler()(w, r, errValue, r.FormValue("error_description"), state)
			return
		}
		codeOpts := make([]CodeExchangeOpt, len(urlParam))
		for i, p := range urlParam {
			codeOpts[i] = CodeExchangeOpt(p)
		}

		if rp.IsPKCE() {
			codeVerifier, err := rp.CookieHandler().CheckCookie(r, pkceCode)
			if err != nil {
				unauthorizedError(w, r, "failed to get code verifier: "+err.Error(), state, rp)
				return
			}
			codeOpts = append(codeOpts, WithCodeVerifier(codeVerifier))
			rp.CookieHandler().DeleteCookie(w, pkceCode)
		}
		if rp.Signer() != nil {
			assertion, err := client.SignedJWTProfileAssertion(rp.OAuthConfig().ClientID, []string{rp.Issuer()}, time.Hour, rp.Signer())
			if err != nil {
				unauthorizedError(w, r, "failed to build assertion: "+err.Error(), state, rp)
				return
			}
			codeOpts = append(codeOpts, WithClientAssertionJWT(assertion))
		}
		tokens, err := CodeExchange[C](r.Context(), r.FormValue("code"), rp, codeOpts...)
		if err != nil {
			unauthorizedError(w, r, "failed to exchange token: "+err.Error(), state, rp)
			return
		}
		callback(w, r, tokens, state, rp)
	}
}

type SubjectGetter interface {
	GetSubject() string
}

type CodeExchangeUserinfoCallback[C oidc.IDClaims, U SubjectGetter] func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], state string, provider RelyingParty, info U)

// UserinfoCallback wraps the callback function of the CodeExchangeHandler
// and calls the userinfo endpoint with the access token
// on success it will pass the userinfo into its callback function as well
func UserinfoCallback[C oidc.IDClaims, U SubjectGetter](f CodeExchangeUserinfoCallback[C, U]) CodeExchangeCallback[C] {
	return func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], state string, rp RelyingParty) {
		ctx, span := client.Tracer.Start(r.Context(), "UserinfoCallback")
		r = r.WithContext(ctx)
		defer span.End()

		info, err := Userinfo[U](r.Context(), tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), rp)
		if err != nil {
			unauthorizedError(w, r, "userinfo failed: "+err.Error(), state, rp)
			return
		}
		f(w, r, tokens, state, rp, info)
	}
}

// Userinfo will call the OIDC [UserInfo] Endpoint with the provided token and returns
// the response in an instance of type U.
// [*oidc.UserInfo] can be used as a good example, or use a custom type if type-safe
// access to custom claims is needed.
//
// [UserInfo]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
func Userinfo[U SubjectGetter](ctx context.Context, token, tokenType, subject string, rp RelyingParty) (userinfo U, err error) {
	var nilU U
	ctx = logCtxWithRPData(ctx, rp, "function", "Userinfo")
	ctx, span := client.Tracer.Start(ctx, "Userinfo")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.UserinfoEndpoint(), nil)
	if err != nil {
		return nilU, err
	}
	req.Header.Set("authorization", tokenType+" "+token)
	if err := httphelper.HttpRequest(rp.HttpClient(), req, &userinfo); err != nil {
		return nilU, err
	}
	if userinfo.GetSubject() != subject {
		return nilU, ErrUserInfoSubNotMatching
	}
	return userinfo, nil
}

func trySetStateCookie(w http.ResponseWriter, state string, rp RelyingParty) error {
	if rp.CookieHandler() != nil {
		if err := rp.CookieHandler().SetCookie(w, stateParam, state); err != nil {
			return err
		}
	}
	return nil
}

func tryReadStateCookie(w http.ResponseWriter, r *http.Request, rp RelyingParty) (state string, err error) {
	if rp.CookieHandler() == nil {
		return r.FormValue(stateParam), nil
	}
	state, err = rp.CookieHandler().CheckQueryCookie(r, stateParam)
	if err != nil {
		return "", err
	}
	rp.CookieHandler().DeleteCookie(w, stateParam)
	return state, nil
}

type OptionFunc func(RelyingParty)

type Endpoints struct {
	oauth2.Endpoint
	IntrospectURL          string
	UserinfoURL            string
	JKWsURL                string
	EndSessionURL          string
	RevokeURL              string
	DeviceAuthorizationURL string
}

func GetEndpoints(discoveryConfig *oidc.DiscoveryConfiguration) Endpoints {
	return Endpoints{
		Endpoint: oauth2.Endpoint{
			AuthURL:  discoveryConfig.AuthorizationEndpoint,
			TokenURL: discoveryConfig.TokenEndpoint,
		},
		IntrospectURL:          discoveryConfig.IntrospectionEndpoint,
		UserinfoURL:            discoveryConfig.UserinfoEndpoint,
		JKWsURL:                discoveryConfig.JwksURI,
		EndSessionURL:          discoveryConfig.EndSessionEndpoint,
		RevokeURL:              discoveryConfig.RevocationEndpoint,
		DeviceAuthorizationURL: discoveryConfig.DeviceAuthorizationEndpoint,
	}
}

// withURLParam sets custom url parameters.
// This is the generalized, unexported, function used by both
// URLParamOpt and AuthURLOpt.
func withURLParam(key, value string) func() []oauth2.AuthCodeOption {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam(key, value),
		}
	}
}

// withPrompt sets the `prompt` params in the auth request
// This is the generalized, unexported, function used by both
// URLParamOpt and AuthURLOpt.
func withPrompt(prompt ...string) func() []oauth2.AuthCodeOption {
	return withURLParam("prompt", oidc.SpaceDelimitedArray(prompt).String())
}

type URLParamOpt func() []oauth2.AuthCodeOption

// WithURLParam allows setting custom key-vale pairs
// to an OAuth2 URL.
func WithURLParam(key, value string) URLParamOpt {
	return withURLParam(key, value)
}

// WithPromptURLParam sets the `prompt` parameter in a URL.
func WithPromptURLParam(prompt ...string) URLParamOpt {
	return withPrompt(prompt...)
}

// WithResponseModeURLParam sets the `response_mode` parameter in a URL.
func WithResponseModeURLParam(mode oidc.ResponseMode) URLParamOpt {
	return withURLParam("response_mode", string(mode))
}

type AuthURLOpt func() []oauth2.AuthCodeOption

// WithCodeChallenge sets the `code_challenge` params in the auth request
func WithCodeChallenge(codeChallenge string) AuthURLOpt {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		}
	}
}

// WithPrompt sets the `prompt` params in the auth request
func WithPrompt(prompt ...string) AuthURLOpt {
	return withPrompt(prompt...)
}

type CodeExchangeOpt func() []oauth2.AuthCodeOption

// WithCodeVerifier sets the `code_verifier` param in the token request
func WithCodeVerifier(codeVerifier string) CodeExchangeOpt {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("code_verifier", codeVerifier)}
	}
}

// WithClientAssertionJWT sets the `client_assertion` param in the token request
func WithClientAssertionJWT(clientAssertion string) CodeExchangeOpt {
	return func() []oauth2.AuthCodeOption {
		return client.ClientAssertionCodeOptions(clientAssertion)
	}
}

type tokenEndpointCaller struct {
	RelyingParty
}

func (t tokenEndpointCaller) TokenEndpoint() string {
	return t.OAuthConfig().Endpoint.TokenURL
}

type RefreshTokenRequest struct {
	RefreshToken        string                   `schema:"refresh_token"`
	Scopes              oidc.SpaceDelimitedArray `schema:"scope,omitempty"`
	ClientID            string                   `schema:"client_id,omitempty"`
	ClientSecret        string                   `schema:"client_secret,omitempty"`
	ClientAssertion     string                   `schema:"client_assertion,omitempty"`
	ClientAssertionType string                   `schema:"client_assertion_type,omitempty"`
	GrantType           oidc.GrantType           `schema:"grant_type"`
}

// RefreshTokens performs a token refresh. If it doesn't error, it will always
// provide a new AccessToken. It may provide a new RefreshToken, and if it does, then
// the old one should be considered invalid.
//
// In case the RP is not OAuth2 only and an IDToken was part of the response,
// the IDToken and AccessToken will be verified
// and the IDToken and IDTokenClaims fields will be populated in the returned object.
func RefreshTokens[C oidc.IDClaims](ctx context.Context, rp RelyingParty, refreshToken, clientAssertion, clientAssertionType string) (*oidc.Tokens[C], error) {
	ctx, span := client.Tracer.Start(ctx, "RefreshTokens")
	defer span.End()

	ctx = logCtxWithRPData(ctx, rp, "function", "RefreshTokens")
	request := RefreshTokenRequest{
		RefreshToken:        refreshToken,
		Scopes:              rp.OAuthConfig().Scopes,
		ClientID:            rp.OAuthConfig().ClientID,
		ClientSecret:        rp.OAuthConfig().ClientSecret,
		ClientAssertion:     clientAssertion,
		ClientAssertionType: clientAssertionType,
		GrantType:           oidc.GrantTypeRefreshToken,
	}
	newToken, err := client.CallTokenEndpoint(ctx, request, tokenEndpointCaller{RelyingParty: rp})
	if err != nil {
		return nil, err
	}
	tokens, err := verifyTokenResponse[C](ctx, newToken, rp)
	if err == nil || errors.Is(err, ErrMissingIDToken) {
		// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
		// ...except that it might not contain an id_token.
		return tokens, nil
	}
	return nil, err
}

func EndSession(ctx context.Context, rp RelyingParty, idToken, optionalRedirectURI, optionalState string) (*url.URL, error) {
	ctx = logCtxWithRPData(ctx, rp, "function", "EndSession")
	ctx, span := client.Tracer.Start(ctx, "RefreshTokens")
	defer span.End()

	request := oidc.EndSessionRequest{
		IdTokenHint:           idToken,
		ClientID:              rp.OAuthConfig().ClientID,
		PostLogoutRedirectURI: optionalRedirectURI,
		State:                 optionalState,
	}
	return client.CallEndSessionEndpoint(ctx, request, nil, rp)
}

// RevokeToken requires a RelyingParty that is also a client.RevokeCaller.  The RelyingParty
// returned by NewRelyingPartyOIDC() meets that criteria, but the one returned by
// NewRelyingPartyOAuth() does not.
//
// tokenTypeHint should be either "id_token" or "refresh_token".
func RevokeToken(ctx context.Context, rp RelyingParty, token string, tokenTypeHint string) error {
	ctx = logCtxWithRPData(ctx, rp, "function", "RevokeToken")
	ctx, span := client.Tracer.Start(ctx, "RefreshTokens")
	defer span.End()
	request := client.RevokeRequest{
		Token:         token,
		TokenTypeHint: tokenTypeHint,
		ClientID:      rp.OAuthConfig().ClientID,
		ClientSecret:  rp.OAuthConfig().ClientSecret,
	}
	if rc, ok := rp.(client.RevokeCaller); ok && rc.GetRevokeEndpoint() != "" {
		return client.CallRevokeEndpoint(ctx, request, nil, rc)
	}
	return ErrRelyingPartyNotSupportRevokeCaller
}

func unauthorizedError(w http.ResponseWriter, r *http.Request, desc string, state string, rp RelyingParty) {
	if rp, ok := rp.(HasUnauthorizedHandler); ok {
		rp.UnauthorizedHandler()(w, r, desc, state)
		return
	}
	http.Error(w, desc, http.StatusUnauthorized)
}

package rp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/oidc/grants"
	"github.com/caos/oidc/pkg/utils"

	"golang.org/x/oauth2"
)

const (
	idTokenKey    = "id_token"
	stateParam    = "state"
	pkceCode      = "pkce"
	jwtProfileKey = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

var (
	encoder = func() utils.Encoder {
		e := schema.NewEncoder()
		e.RegisterEncoder(oidc.Scopes{}, func(value reflect.Value) string {
			return value.Interface().(oidc.Scopes).Encode()
		})
		return e
	}()
)

//RelayingParty declares the minimal interface for oidc clients
type RelayingParty interface {
	//OAuthConfig returns the oauth2 Config
	OAuthConfig() *oauth2.Config

	//IsPKCE returns if authorization is done using `Authorization Code Flow with Proof Key for Code Exchange (PKCE)`
	IsPKCE() bool

	//CookieHandler returns a http cookie handler used for various state transfer cookies
	CookieHandler() *utils.CookieHandler

	//HttpClient returns a http client used for calls to the openid provider, e.g. calling token endpoint
	HttpClient() *http.Client

	//IsOAuth2Only specifies whether relaying party handles only oauth2 or oidc calls
	IsOAuth2Only() bool

	ClientKey() []byte
	ClientKeyID() string

	//IDTokenVerifier returns the verifier interface used for oidc id_token verification
	IDTokenVerifier() IDTokenVerifier

	//ErrorHandler returns the handler used for callback errors
	ErrorHandler() func(http.ResponseWriter, *http.Request, string, string, string)
}

type ErrorHandler func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, state string)

var (
	DefaultErrorHandler ErrorHandler = func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, state string) {
		http.Error(w, errorType+": "+errorDesc, http.StatusInternalServerError)
	}
)

type relayingParty struct {
	issuer      string
	endpoints   Endpoints
	oauthConfig *oauth2.Config
	oauth2Only  bool
	pkce        bool
	clientKey   []byte
	clientKeyID string

	httpClient    *http.Client
	cookieHandler *utils.CookieHandler

	errorHandler    func(http.ResponseWriter, *http.Request, string, string, string)
	idTokenVerifier IDTokenVerifier
	verifierOpts    []VerifierOption
}

func (rp *relayingParty) OAuthConfig() *oauth2.Config {
	return rp.oauthConfig
}

func (rp *relayingParty) IsPKCE() bool {
	return rp.pkce
}

func (rp *relayingParty) CookieHandler() *utils.CookieHandler {
	return rp.cookieHandler
}

func (rp *relayingParty) HttpClient() *http.Client {
	return rp.httpClient
}

func (rp *relayingParty) IsOAuth2Only() bool {
	return rp.oauth2Only
}

func (rp *relayingParty) ClientKey() []byte {
	return rp.clientKey
}

func (rp *relayingParty) ClientKeyID() string {
	return rp.clientKeyID
}

func (rp *relayingParty) IDTokenVerifier() IDTokenVerifier {
	if rp.idTokenVerifier == nil {
		rp.idTokenVerifier = NewIDTokenVerifier(rp.issuer, rp.oauthConfig.ClientID, NewRemoteKeySet(rp.httpClient, rp.endpoints.JKWsURL), rp.verifierOpts...)
	}
	return rp.idTokenVerifier
}

func (rp *relayingParty) ErrorHandler() func(http.ResponseWriter, *http.Request, string, string, string) {
	if rp.errorHandler == nil {
		rp.errorHandler = DefaultErrorHandler
	}
	return rp.errorHandler
}

//NewRelayingPartyOAuth creates an (OAuth2) RelayingParty with the given
//OAuth2 Config and possible configOptions
//it will use the AuthURL and TokenURL set in config
func NewRelayingPartyOAuth(config *oauth2.Config, options ...Option) (RelayingParty, error) {
	rp := &relayingParty{
		oauthConfig: config,
		httpClient:  utils.DefaultHTTPClient,
		oauth2Only:  true,
	}

	for _, optFunc := range options {
		optFunc(rp)
	}

	return rp, nil
}

//NewRelayingPartyOIDC creates an (OIDC) RelayingParty with the given
//issuer, clientID, clientSecret, redirectURI, scopes and possible configOptions
//it will run discovery on the provided issuer and use the found endpoints
func NewRelayingPartyOIDC(issuer, clientID, clientSecret, redirectURI string, scopes []string, options ...Option) (RelayingParty, error) {
	rp := &relayingParty{
		issuer: issuer,
		oauthConfig: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Scopes:       scopes,
		},
		httpClient: utils.DefaultHTTPClient,
		oauth2Only: false,
	}

	for _, optFunc := range options {
		optFunc(rp)
	}

	endpoints, err := Discover(rp.issuer, rp.httpClient)
	if err != nil {
		return nil, err
	}
	rp.oauthConfig.Endpoint = endpoints.Endpoint
	rp.endpoints = endpoints

	return rp, nil
}

//DefaultRPOpts is the type for providing dynamic options to the DefaultRP
type Option func(*relayingParty)

//WithCookieHandler set a `CookieHandler` for securing the various redirects
func WithCookieHandler(cookieHandler *utils.CookieHandler) Option {
	return func(rp *relayingParty) {
		rp.cookieHandler = cookieHandler
	}
}

//WithPKCE sets the RP to use PKCE (oauth2 code challenge)
//it also sets a `CookieHandler` for securing the various redirects
//and exchanging the code challenge
func WithPKCE(cookieHandler *utils.CookieHandler) Option {
	return func(rp *relayingParty) {
		rp.pkce = true
		rp.cookieHandler = cookieHandler
	}
}

//WithHTTPClient provides the ability to set an http client to be used for the relaying party and verifier
func WithHTTPClient(client *http.Client) Option {
	return func(rp *relayingParty) {
		rp.httpClient = client
	}
}

func WithErrorHandler(errorHandler ErrorHandler) Option {
	return func(rp *relayingParty) {
		rp.errorHandler = errorHandler
	}
}

func WithVerifierOpts(opts ...VerifierOption) Option {
	return func(rp *relayingParty) {
		rp.verifierOpts = opts
	}
}

//Discover calls the discovery endpoint of the provided issuer and returns the found endpoints
func Discover(issuer string, httpClient *http.Client) (Endpoints, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + oidc.DiscoveryEndpoint
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return Endpoints{}, err
	}
	discoveryConfig := new(oidc.DiscoveryConfiguration)
	err = utils.HttpRequest(httpClient, req, &discoveryConfig)
	if err != nil {
		return Endpoints{}, err
	}
	return GetEndpoints(discoveryConfig), nil
}

//AuthURL returns the auth request url
//(wrapping the oauth2 `AuthCodeURL`)
func AuthURL(state string, rp RelayingParty, opts ...AuthURLOpt) string {
	authOpts := make([]oauth2.AuthCodeOption, 0)
	for _, opt := range opts {
		authOpts = append(authOpts, opt()...)
	}
	return rp.OAuthConfig().AuthCodeURL(state, authOpts...)
}

//AuthURLHandler extends the `AuthURL` method with a http redirect handler
//including handling setting cookie for secure `state` transfer
func AuthURLHandler(stateFn func() string, rp RelayingParty) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts := make([]AuthURLOpt, 0)
		state := stateFn()
		if err := trySetStateCookie(w, state, rp); err != nil {
			http.Error(w, "failed to create state cookie: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if rp.IsPKCE() {
			codeChallenge, err := GenerateAndStoreCodeChallenge(w, rp)
			if err != nil {
				http.Error(w, "failed to create code challenge: "+err.Error(), http.StatusUnauthorized)
				return
			}
			opts = append(opts, WithCodeChallenge(codeChallenge))
		}
		http.Redirect(w, r, AuthURL(state, rp, opts...), http.StatusFound)
	}
}

//GenerateAndStoreCodeChallenge generates a PKCE code challenge and stores its verifier into a secure cookie
func GenerateAndStoreCodeChallenge(w http.ResponseWriter, rp RelayingParty) (string, error) {
	codeVerifier := uuid.New().String()
	if err := rp.CookieHandler().SetCookie(w, pkceCode, codeVerifier); err != nil {
		return "", err
	}
	return oidc.NewSHACodeChallenge(codeVerifier), nil
}

//CodeExchange handles the oauth2 code exchange, extracting and validating the id_token
//returning it parsed together with the oauth2 tokens (access, refresh)
func CodeExchange(ctx context.Context, code string, rp RelayingParty, opts ...CodeExchangeOpt) (tokens *oidc.Tokens, err error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, rp.HttpClient())
	codeOpts := make([]oauth2.AuthCodeOption, 0)
	for _, opt := range opts {
		codeOpts = append(codeOpts, opt()...)
	}

	token, err := rp.OAuthConfig().Exchange(ctx, code, codeOpts...)
	if err != nil {
		return nil, err
	}

	if rp.IsOAuth2Only() {
		return &oidc.Tokens{Token: token}, nil
	}

	idTokenString, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return nil, errors.New("id_token missing")
	}

	idToken, err := VerifyTokens(ctx, token.AccessToken, idTokenString, rp.IDTokenVerifier())
	if err != nil {
		return nil, err
	}

	return &oidc.Tokens{Token: token, IDTokenClaims: idToken, IDToken: idTokenString}, nil
}

//CodeExchangeHandler extends the `CodeExchange` method with a http handler
//including cookie handling for secure `state` transfer
//and optional PKCE code verifier checking
func CodeExchangeHandler(callback func(http.ResponseWriter, *http.Request, *oidc.Tokens, string), rp RelayingParty) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := tryReadStateCookie(w, r, rp)
		if err != nil {
			http.Error(w, "failed to get state: "+err.Error(), http.StatusUnauthorized)
			return
		}
		params := r.URL.Query()
		if params.Get("error") != "" {
			rp.ErrorHandler()(w, r, params.Get("error"), params.Get("error_description"), state)
			return
		}
		codeOpts := make([]CodeExchangeOpt, 0)
		if rp.IsPKCE() {
			codeVerifier, err := rp.CookieHandler().CheckCookie(r, pkceCode)
			if err != nil {
				http.Error(w, "failed to get code verifier: "+err.Error(), http.StatusUnauthorized)
				return
			}
			codeOpts = append(codeOpts, WithCodeVerifier(codeVerifier))
		}
		//if len(rp.ClientKey()) > 0 {
		//	assertion, err := oidc.NewJWTProfileAssertionStringFromFileData(rp.ClientKey(), []string{rp.OAuthConfig().Endpoint.TokenURL})
		//	if err != nil {
		//		http.Error(w, "failed to build assertion: "+err.Error(), http.StatusUnauthorized)
		//		return
		//	}
		//	codeOpts = append(codeOpts, WithClientAssertionJWT(assertion))
		//}
		tokens, err := CodeExchange(r.Context(), params.Get("code"), rp, codeOpts...)
		if err != nil {
			http.Error(w, "failed to exchange token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		callback(w, r, tokens, state)
	}
}

//ClientCredentials is the `RelayingParty` interface implementation
//handling the oauth2 client credentials grant
func ClientCredentials(ctx context.Context, rp RelayingParty, scopes ...string) (newToken *oauth2.Token, err error) {
	return CallTokenEndpointAuthorized(grants.ClientCredentialsGrantBasic(scopes...), rp)
}

func CallTokenEndpointAuthorized(request interface{}, rp RelayingParty) (newToken *oauth2.Token, err error) {
	config := rp.OAuthConfig()
	var fn interface{} = utils.AuthorizeBasic(config.ClientID, config.ClientSecret)
	if config.Endpoint.AuthStyle == oauth2.AuthStyleInParams {
		fn = func(form url.Values) {
			form.Set("client_id", config.ClientID)
			form.Set("client_secret", config.ClientSecret)
		}
	}
	return callTokenEndpoint(request, fn, rp)
}

func CallTokenEndpoint(request interface{}, rp RelayingParty) (newToken *oauth2.Token, err error) {
	return callTokenEndpoint(request, nil, rp)
}

func callTokenEndpoint(request interface{}, authFn interface{}, rp RelayingParty) (newToken *oauth2.Token, err error) {
	req, err := utils.FormRequest(rp.OAuthConfig().Endpoint.TokenURL, request, encoder, authFn)
	if err != nil {
		return nil, err
	}
	var tokenRes struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := utils.HttpRequest(rp.HttpClient(), req, &tokenRes); err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken:  tokenRes.AccessToken,
		TokenType:    tokenRes.TokenType,
		RefreshToken: tokenRes.RefreshToken,
		Expiry:       time.Now().UTC().Add(time.Duration(tokenRes.ExpiresIn) * time.Second),
	}, nil
}

func trySetStateCookie(w http.ResponseWriter, state string, rp RelayingParty) error {
	if rp.CookieHandler() != nil {
		if err := rp.CookieHandler().SetCookie(w, stateParam, state); err != nil {
			return err
		}
	}
	return nil
}

func tryReadStateCookie(w http.ResponseWriter, r *http.Request, rp RelayingParty) (state string, err error) {
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

type OptionFunc func(RelayingParty)

type Endpoints struct {
	oauth2.Endpoint
	IntrospectURL string
	UserinfoURL   string
	JKWsURL       string
}

func GetEndpoints(discoveryConfig *oidc.DiscoveryConfiguration) Endpoints {
	return Endpoints{
		Endpoint: oauth2.Endpoint{
			AuthURL:   discoveryConfig.AuthorizationEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
			TokenURL:  discoveryConfig.TokenEndpoint,
		},
		IntrospectURL: discoveryConfig.IntrospectionEndpoint,
		UserinfoURL:   discoveryConfig.UserinfoEndpoint,
		JKWsURL:       discoveryConfig.JwksURI,
	}
}

type AuthURLOpt func() []oauth2.AuthCodeOption

//WithCodeChallenge sets the `code_challenge` params in the auth request
func WithCodeChallenge(codeChallenge string) AuthURLOpt {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		}
	}
}

//WithPrompt sets the `prompt` params in the auth request
func WithPrompt(prompt oidc.Prompt) AuthURLOpt {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("prompt", string(prompt)),
		}
	}
}

type CodeExchangeOpt func() []oauth2.AuthCodeOption

//WithCodeVerifier sets the `code_verifier` param in the token request
func WithCodeVerifier(codeVerifier string) CodeExchangeOpt {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("code_verifier", codeVerifier)}
	}
}

//WithClientAssertionJWT sets the `client_assertion` param in the token request
func WithClientAssertionJWT(clientAssertion string) CodeExchangeOpt {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("client_assertion", clientAssertion),
			oauth2.SetAuthURLParam("client_assertion_type", oidc.ClientAssertionTypeJWTAssertion),
		}
	}
}

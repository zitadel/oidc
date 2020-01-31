package rp

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/caos/oidc/pkg/oidc/grants"

	"golang.org/x/oauth2"

	"github.com/caos/oidc/pkg/oidc"
	grants_tx "github.com/caos/oidc/pkg/oidc/grants/tokenexchange"
	"github.com/caos/oidc/pkg/utils"
)

const (
	idTokenKey = "id_token"
	stateParam = "state"
	pkceCode   = "pkce"
)

var (
	DefaultErrorHandler = func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, state string) {
		http.Error(w, errorType+": "+errorDesc, http.StatusInternalServerError)
	}
)

//DefaultRP impements the `DelegationTokenExchangeRP` interface extending the `RelayingParty` interface
type DefaultRP struct {
	endpoints Endpoints

	oauthConfig oauth2.Config
	config      *Config
	pkce        bool

	httpClient    *http.Client
	cookieHandler *utils.CookieHandler

	errorHandler func(http.ResponseWriter, *http.Request, string, string, string)

	verifier Verifier
}

//NewDefaultRP creates `DefaultRP` with the given
//Config and possible configOptions
//it will run discovery on the provided issuer
//if no verifier is provided using the options the `DefaultVerifier` is set
func NewDefaultRP(rpConfig *Config, rpOpts ...DefaultRPOpts) (DelegationTokenExchangeRP, error) {
	p := &DefaultRP{
		config:     rpConfig,
		httpClient: utils.DefaultHTTPClient,
	}

	for _, optFunc := range rpOpts {
		optFunc(p)
	}

	if err := p.discover(); err != nil {
		return nil, err
	}

	if p.errorHandler == nil {
		p.errorHandler = DefaultErrorHandler
	}

	if p.verifier == nil {
		p.verifier = NewDefaultVerifier(rpConfig.Issuer, rpConfig.ClientID, NewRemoteKeySet(p.httpClient, p.endpoints.JKWsURL))
	}

	return p, nil
}

//DefaultRPOpts is the type for providing dynamic options to the DefaultRP
type DefaultRPOpts func(p *DefaultRP)

//WithCookieHandler set a `CookieHandler` for securing the various redirects
func WithCookieHandler(cookieHandler *utils.CookieHandler) DefaultRPOpts {
	return func(p *DefaultRP) {
		p.cookieHandler = cookieHandler
	}
}

//WithPKCE sets the RP to use PKCE (oauth2 code challenge)
//it also sets a `CookieHandler` for securing the various redirects
//and exchanging the code challenge
func WithPKCE(cookieHandler *utils.CookieHandler) DefaultRPOpts {
	return func(p *DefaultRP) {
		p.pkce = true
		p.cookieHandler = cookieHandler
	}
}

//WithHTTPClient provides the ability to set an http client to be used for the relaying party and verifier
func WithHTTPClient(client *http.Client) DefaultRPOpts {
	return func(p *DefaultRP) {
		p.httpClient = client
	}
}

//AuthURL is the `RelayingParty` interface implementation
//wrapping the oauth2 `AuthCodeURL`
//returning the url of the auth request
func (p *DefaultRP) AuthURL(state string, opts ...AuthURLOpt) string {
	authOpts := make([]oauth2.AuthCodeOption, 0)
	for _, opt := range opts {
		authOpts = append(authOpts, opt()...)
	}
	return p.oauthConfig.AuthCodeURL(state, authOpts...)
}

//AuthURL is the `RelayingParty` interface implementation
//extending the `AuthURL` method with a http redirect handler
func (p *DefaultRP) AuthURLHandler(state string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts := make([]AuthURLOpt, 0)
		if err := p.trySetStateCookie(w, state); err != nil {
			http.Error(w, "failed to create state cookie: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if p.pkce {
			codeChallenge, err := p.generateAndStoreCodeChallenge(w)
			if err != nil {
				http.Error(w, "failed to create code challenge: "+err.Error(), http.StatusUnauthorized)
				return
			}
			opts = append(opts, WithCodeChallenge(codeChallenge))
		}
		http.Redirect(w, r, p.AuthURL(state, opts...), http.StatusFound)
	}
}

func (p *DefaultRP) generateAndStoreCodeChallenge(w http.ResponseWriter) (string, error) {
	var codeVerifier string
	codeVerifier = "s"
	if err := p.cookieHandler.SetCookie(w, pkceCode, codeVerifier); err != nil {
		return "", err
	}
	return oidc.NewSHACodeChallenge(codeVerifier), nil
}

//AuthURL is the `RelayingParty` interface implementation
//handling the oauth2 code exchange, extracting and validating the id_token
//returning it paresed together with the oauth2 tokens (access, refresh)
func (p *DefaultRP) CodeExchange(ctx context.Context, code string, opts ...CodeExchangeOpt) (tokens *oidc.Tokens, err error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	codeOpts := make([]oauth2.AuthCodeOption, 0)
	for _, opt := range opts {
		codeOpts = append(codeOpts, opt()...)
	}

	token, err := p.oauthConfig.Exchange(ctx, code, codeOpts...)
	if err != nil {
		return nil, err //TODO: our error
	}
	idTokenString, ok := token.Extra(idTokenKey).(string)
	if !ok {
		//TODO: implement
	}

	idToken, err := p.verifier.Verify(ctx, token.AccessToken, idTokenString)
	if err != nil {
		return nil, err //TODO: err
	}

	return &oidc.Tokens{Token: token, IDTokenClaims: idToken, IDToken: idTokenString}, nil
}

//AuthURL is the `RelayingParty` interface implementation
//extending the `CodeExchange` method with callback function
func (p *DefaultRP) CodeExchangeHandler(callback func(http.ResponseWriter, *http.Request, *oidc.Tokens, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := p.tryReadStateCookie(w, r)
		if err != nil {
			http.Error(w, "failed to get state: "+err.Error(), http.StatusUnauthorized)
			return
		}
		params := r.URL.Query()
		if params.Get("error") != "" {
			p.errorHandler(w, r, params.Get("error"), params.Get("error_description"), state)
			return
		}
		codeOpts := make([]CodeExchangeOpt, 0)
		if p.pkce {
			codeVerifier, err := p.cookieHandler.CheckCookie(r, pkceCode)
			if err != nil {
				http.Error(w, "failed to get code verifier: "+err.Error(), http.StatusUnauthorized)
				return
			}
			codeOpts = append(codeOpts, WithCodeVerifier(codeVerifier))
		}
		tokens, err := p.CodeExchange(r.Context(), params.Get("code"), codeOpts...)
		if err != nil {
			http.Error(w, "failed to exchange token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		callback(w, r, tokens, state)
	}
}

// func (p *DefaultRP) Introspect(ctx context.Context, accessToken string) (oidc.TokenIntrospectResponse, error) {
// 	// req := &http.Request{}
// 	// resp, err := p.httpClient.Do(req)
// 	// if err != nil {

// 	// }
// 	// p.endpoints.IntrospectURL
// 	return nil, nil
// }

func (p *DefaultRP) Userinfo() {}

//ClientCredentials is the `RelayingParty` interface implementation
//handling the oauth2 client credentials grant
func (p *DefaultRP) ClientCredentials(ctx context.Context, scopes ...string) (newToken *oauth2.Token, err error) {
	return p.callTokenEndpoint(grants.ClientCredentialsGrantBasic(scopes...))
}

//TokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange (draft)
func (p *DefaultRP) TokenExchange(ctx context.Context, request *grants_tx.TokenExchangeRequest) (newToken *oauth2.Token, err error) {
	return p.callTokenEndpoint(request)
}

//DelegationTokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange for a delegation token (draft)
func (p *DefaultRP) DelegationTokenExchange(ctx context.Context, subjectToken string, reqOpts ...grants_tx.TokenExchangeOption) (newToken *oauth2.Token, err error) {
	return p.TokenExchange(ctx, DelegationTokenRequest(subjectToken, reqOpts...))
}

func (p *DefaultRP) discover() error {
	wellKnown := strings.TrimSuffix(p.config.Issuer, "/") + oidc.DiscoveryEndpoint
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return err
	}
	discoveryConfig := new(oidc.DiscoveryConfiguration)
	err = utils.HttpRequest(p.httpClient, req, &discoveryConfig)
	if err != nil {
		return err
	}
	p.endpoints = GetEndpoints(discoveryConfig)
	p.oauthConfig = oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     p.endpoints.Endpoint,
		RedirectURL:  p.config.CallbackURL,
		Scopes:       p.config.Scopes,
	}
	return nil
}

func (p *DefaultRP) callTokenEndpoint(request interface{}) (newToken *oauth2.Token, err error) {
	req, err := utils.FormRequest(p.endpoints.TokenURL, request)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(p.config.ClientID + ":" + p.config.ClientSecret))
	req.Header.Set("Authorization", "Basic "+auth)
	token := new(oauth2.Token)
	if err := utils.HttpRequest(p.httpClient, req, token); err != nil {
		return nil, err
	}
	return token, nil
}

func (p *DefaultRP) trySetStateCookie(w http.ResponseWriter, state string) error {
	if p.cookieHandler != nil {
		if err := p.cookieHandler.SetCookie(w, stateParam, state); err != nil {
			return err
		}
	}
	return nil
}

func (p *DefaultRP) tryReadStateCookie(w http.ResponseWriter, r *http.Request) (state string, err error) {
	if p.cookieHandler == nil {
		return r.FormValue(stateParam), nil
	}
	state, err = p.cookieHandler.CheckQueryCookie(r, stateParam)
	if err != nil {
		return "", err
	}
	p.cookieHandler.DeleteCookie(w, stateParam)
	return state, nil
}

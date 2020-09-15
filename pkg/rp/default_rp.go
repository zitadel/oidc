package rp

import (
	"context"
	"net/http"
	"strings"

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

//deprecated: use NewRelayingParty instead
//DefaultRP implements the `DelegationTokenExchangeRP` interface extending the `RelayingParty` interface
type DefaultRP struct {
	endpoints Endpoints

	oauthConfig oauth2.Config
	config      *Config
	pkce        bool

	httpClient    *http.Client
	cookieHandler *utils.CookieHandler

	errorHandler func(http.ResponseWriter, *http.Request, string, string, string)

	idTokenVerifier IDTokenVerifier
	verifierOpts    []ConfFunc
	onlyOAuth2      bool
}

func (p *DefaultRP) ErrorHandler() func(http.ResponseWriter, *http.Request, string, string, string) {
	return p.errorHandler
}

func (p *DefaultRP) OAuthConfig() *oauth2.Config {
	return &p.oauthConfig
}

func (p *DefaultRP) IsPKCE() bool {
	return p.pkce
}

func (p *DefaultRP) CookieHandler() *utils.CookieHandler {
	return p.cookieHandler
}

func (p *DefaultRP) HttpClient() *http.Client {
	return p.httpClient
}

func (p *DefaultRP) IsOAuth2Only() bool {
	return p.onlyOAuth2
}

func (p *DefaultRP) IDTokenVerifier() IDTokenVerifier {
	return p.idTokenVerifier
}

//deprecated: use NewRelayingParty instead
//
//NewDefaultRP creates `DefaultRP` with the given
//Config and possible configOptions
//it will run discovery on the provided issuer
//if no verifier is provided using the options the `DefaultVerifier` is set
func NewDefaultRP(rpConfig *Config, rpOpts ...DefaultRPOpts) (DelegationTokenExchangeRP, error) {
	foundOpenID := false
	for _, scope := range rpConfig.Scopes {
		if scope == "openid" {
			foundOpenID = true
		}
	}

	p := &DefaultRP{
		config:     rpConfig,
		httpClient: utils.DefaultHTTPClient,
		onlyOAuth2: !foundOpenID,
	}

	for _, optFunc := range rpOpts {
		optFunc(p)
	}

	if rpConfig.Endpoints.TokenURL != "" && rpConfig.Endpoints.AuthURL != "" {
		p.oauthConfig = p.getOAuthConfig(rpConfig.Endpoints)
	} else {
		if err := p.discover(); err != nil {
			return nil, err
		}
	}

	if p.errorHandler == nil {
		p.errorHandler = DefaultErrorHandler
	}

	if p.idTokenVerifier == nil {
		p.idTokenVerifier = NewIDTokenVerifier(rpConfig.Issuer, rpConfig.ClientID, NewRemoteKeySet(p.httpClient, p.endpoints.JKWsURL))
	}

	return p, nil
}

//DefaultRPOpts is the type for providing dynamic options to the DefaultRP
type DefaultRPOpts func(p *DefaultRP)

/*
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

func WithVerifierOpts(opts ...ConfFunc) DefaultRPOpts {
	return func(p *DefaultRP) {
		p.verifierOpts = opts
	}
}
*/

//AuthURL is the `RelayingParty` interface implementation
//wrapping the oauth2 `AuthCodeURL`
//returning the url of the auth request
func (p *DefaultRP) AuthURL(state string, opts ...AuthURLOpt) string {
	return AuthURL(state, p, opts...)
}

//AuthURL is the `RelayingParty` interface implementation
//extending the `AuthURL` method with a http redirect handler
func (p *DefaultRP) AuthURLHandler(state string) http.HandlerFunc {
	return AuthURLHandler(
		func() string {
			return state
		}, p,
	)
}

//deprecated: Use CodeExchange func and provide a RelayingParty
//
//AuthURL is the `RelayingParty` interface implementation
//handling the oauth2 code exchange, extracting and validating the id_token
//returning it parsed together with the oauth2 tokens (access, refresh)
func (p *DefaultRP) CodeExchange(ctx context.Context, code string, opts ...CodeExchangeOpt) (tokens *oidc.Tokens, err error) {
	return CodeExchange(ctx, code, p, opts...)
}

//AuthURL is the `RelayingParty` interface implementation
//extending the `CodeExchange` method with callback function
func (p *DefaultRP) CodeExchangeHandler(callback func(http.ResponseWriter, *http.Request, *oidc.Tokens, string)) http.HandlerFunc {
	return CodeExchangeHandler(callback, p)
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
	return ClientCredentials(ctx, p, scopes...)
}

//TokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange (draft)
func (p *DefaultRP) TokenExchange(ctx context.Context, request *grants_tx.TokenExchangeRequest) (newToken *oauth2.Token, err error) {
	return TokenExchange(ctx, request, p)
}

//DelegationTokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange for a delegation token (draft)
func (p *DefaultRP) DelegationTokenExchange(ctx context.Context, subjectToken string, reqOpts ...grants_tx.TokenExchangeOption) (newToken *oauth2.Token, err error) {
	return TokenExchange(ctx, DelegationTokenRequest(subjectToken, reqOpts...), p)
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
	p.oauthConfig = p.getOAuthConfig(p.endpoints.Endpoint)
	return nil
}

func (p *DefaultRP) getOAuthConfig(endpoint oauth2.Endpoint) oauth2.Config {
	return oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  p.config.CallbackURL,
		Scopes:       p.config.Scopes,
	}
}

func (p *DefaultRP) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	return p.oauthConfig.Client(ctx, token)
}

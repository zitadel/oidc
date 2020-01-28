package rp

import (
	"context"
	"net/http"

	"github.com/caos/oidc/pkg/oidc"

	"golang.org/x/oauth2"
)

//RelayingParty declares the minimal interface for oidc clients
type RelayingParty interface {

	//AuthURL returns the authorization endpoint with a given state
	AuthURL(state string, opts ...AuthURLOpt) string

	//AuthURLHandler should implement the AuthURL func as http.HandlerFunc
	//(redirecting to the auth endpoint)
	AuthURLHandler(state string) http.HandlerFunc

	//CodeExchange implements the OIDC Token Request (oauth2 Authorization Code Grant)
	//returning an `Access Token` and `ID Token Claims`
	CodeExchange(ctx context.Context, code string, opts ...CodeExchangeOpt) (*oidc.Tokens, error)

	//CodeExchangeHandler extends the CodeExchange func,
	//calling the provided callback func on success with additional returned `state`
	CodeExchangeHandler(callback func(http.ResponseWriter, *http.Request, *oidc.Tokens, string)) http.HandlerFunc

	//ClientCredentials implements the oauth2 Client Credentials Grant
	//requesting an `Access Token` for the client itself, without user context
	ClientCredentials(ctx context.Context, scopes ...string) (*oauth2.Token, error)

	//Introspects calls the Introspect Endpoint
	//for validating an (access) token
	// Introspect(ctx context.Context, token string) (TokenIntrospectResponse, error)

	//Userinfo implements the OIDC Userinfo call
	//returning the info of the user for the requested scopes of an access token
	Userinfo()
}

//PasswortGrantRP extends the `RelayingParty` interface with the oauth2 `Password Grant`
//
//This interface is separated from the standard `RelayingParty` interface as the `password grant`
//is part of the oauth2 and therefore OIDC specification, but should only be used when there's no
//other possibility, so IMHO never ever. Ever.
type PasswortGrantRP interface {
	RelayingParty

	//PasswordGrant implements the oauth2 `Password Grant`,
	//requesting an access token with the users `username` and `password`
	PasswordGrant(context.Context, string, string) (*oauth2.Token, error)
}

type Config struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Issuer       string
	Scopes       []string
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

type CodeExchangeOpt func() []oauth2.AuthCodeOption

//WithCodeVerifier sets the `code_verifier` param in the token request
func WithCodeVerifier(codeVerifier string) CodeExchangeOpt {
	return func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("code_verifier", codeVerifier)}
	}
}

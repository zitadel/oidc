package tokenexchange

import (
	"errors"
	"net/http"

	"github.com/zitadel/oidc/v2/pkg/client"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type TokenExchanger interface {
	TokenEndpoint() string
	HttpClient() *http.Client
	AuthFn() (any, error)
}

type OAuthTokenExchange struct {
	httpClient    *http.Client
	tokenEndpoint string
	authFn        func() (any, error)
}

func NewTokenExchanger(issuer string, options ...func(source *OAuthTokenExchange)) (TokenExchanger, error) {
	return newOAuthTokenExchange(issuer, nil, options...)
}

func NewTokenExchangerClientCredentials(issuer, clientID, clientSecret string, options ...func(source *OAuthTokenExchange)) (TokenExchanger, error) {
	authorizer := func() (any, error) {
		return httphelper.AuthorizeBasic(clientID, clientSecret), nil
	}
	return newOAuthTokenExchange(issuer, authorizer, options...)
}

func newOAuthTokenExchange(issuer string, authorizer func() (any, error), options ...func(source *OAuthTokenExchange)) (*OAuthTokenExchange, error) {
	te := &OAuthTokenExchange{
		httpClient: httphelper.DefaultHTTPClient,
	}
	for _, opt := range options {
		opt(te)
	}

	if te.tokenEndpoint == "" {
		config, err := client.Discover(issuer, te.httpClient)
		if err != nil {
			return nil, err
		}

		te.tokenEndpoint = config.TokenEndpoint
	}

	if te.tokenEndpoint == "" {
		return nil, errors.New("tokenURL is empty: please provide with either `WithStaticTokenEndpoint` or a discovery url")
	}

	te.authFn = authorizer

	return te, nil
}

func WithHTTPClient(client *http.Client) func(*OAuthTokenExchange) {
	return func(source *OAuthTokenExchange) {
		source.httpClient = client
	}
}

func WithStaticTokenEndpoint(issuer, tokenEndpoint string) func(*OAuthTokenExchange) {
	return func(source *OAuthTokenExchange) {
		source.tokenEndpoint = tokenEndpoint
	}
}

func (te *OAuthTokenExchange) TokenEndpoint() string {
	return te.tokenEndpoint
}

func (te *OAuthTokenExchange) HttpClient() *http.Client {
	return te.httpClient
}

func (te *OAuthTokenExchange) AuthFn() (any, error) {
	if te.authFn != nil {
		return te.authFn()
	}

	return nil, nil
}

// ExchangeToken sends a token exchange request (rfc 8693) to te's token endpoint.
// SubjectToken and SubjectTokenType are required parameters.
func ExchangeToken(
	te TokenExchanger,
	SubjectToken string,
	SubjectTokenType oidc.TokenType,
	ActorToken string,
	ActorTokenType oidc.TokenType,
	Resource []string,
	Audience []string,
	Scopes []string,
	RequestedTokenType oidc.TokenType,
) (*oidc.TokenExchangeResponse, error) {
	if SubjectToken == "" {
		return nil, errors.New("empty subject_token")
	}
	if SubjectTokenType == "" {
		return nil, errors.New("empty subject_token_type")
	}

	authFn, err := te.AuthFn()
	if err != nil {
		return nil, err
	}

	request := oidc.TokenExchangeRequest{
		GrantType:          oidc.GrantTypeTokenExchange,
		SubjectToken:       SubjectToken,
		SubjectTokenType:   SubjectTokenType,
		ActorToken:         ActorToken,
		ActorTokenType:     ActorTokenType,
		Resource:           Resource,
		Audience:           Audience,
		Scopes:             Scopes,
		RequestedTokenType: RequestedTokenType,
	}

	return client.CallTokenExchangeEndpoint(request, authFn, te)
}

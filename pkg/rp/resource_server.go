package rp

import (
	"context"
	"errors"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/jwt"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type ResourceServer interface {
	IntrospectionURL() string
	HttpClient() *http.Client
}

type resourceServer struct {
	issuer        string
	tokenURL      string
	introspectURL string
	httpClient    *http.Client
}

func (r *resourceServer) IntrospectionURL() string {
	return r.introspectURL
}

func (r *resourceServer) HttpClient() *http.Client {
	return r.httpClient
}

func NewResourceServerClientCredentials(issuer, clientID, clientSecret string, option RSOption) (ResourceServer, error) {
	authorizer := func(tokenURL string) func(ctx context.Context) *http.Client {
		return (&clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
		}).Client
	}
	return newResourceServer(issuer, authorizer, option)
}
func NewResourceServerJWTProfile(issuer, clientID, keyID string, key []byte, options ...RSOption) (ResourceServer, error) {
	authorizer := func(tokenURL string) func(ctx context.Context) *http.Client {
		return (&jwt.Config{
			Email:        clientID,
			Subject:      clientID,
			PrivateKey:   key,
			PrivateKeyID: keyID,
			Audience:     issuer,
			TokenURL:     tokenURL,
		}).Client
	}
	return newResourceServer(issuer, authorizer, options...)
}

func newResourceServer(issuer string, authorizer func(tokenURL string) func(ctx context.Context) *http.Client, options ...RSOption) (*resourceServer, error) {
	rp := &resourceServer{
		issuer:     issuer,
		httpClient: utils.DefaultHTTPClient,
	}
	for _, optFunc := range options {
		optFunc(rp)
	}
	if rp.introspectURL == "" || rp.tokenURL == "" {
		endpoints, err := Discover(rp.issuer, rp.httpClient)
		if err != nil {
			return nil, err
		}
		rp.tokenURL = endpoints.TokenURL
		rp.introspectURL = endpoints.IntrospectURL
	}
	if rp.introspectURL == "" || rp.tokenURL == "" {
		return nil, errors.New("introspectURL and/or tokenURL is empty: please provide with either `WithStaticEndpoints` or a discovery url")
	}
	rp.httpClient = authorizer(rp.tokenURL)(context.WithValue(context.Background(), oauth2.HTTPClient, rp.HttpClient()))
	return rp, nil
}

func NewResourceServerFromKeyFile(path string, options ...RSOption) (ResourceServer, error) {
	c, err := ConfigFromKeyFile(path)
	if err != nil {
		return nil, err
	}
	return NewResourceServerJWTProfile(c.Issuer, c.ClientID, c.KeyID, []byte(c.Key), options...)
}

type RSOption func(*resourceServer)

//WithClient provides the ability to set an http client to be used for the resource server
func WithClient(client *http.Client) RSOption {
	return func(server *resourceServer) {
		server.httpClient = client
	}
}

//WithStaticEndpoints provides the ability to set static token and introspect URL
func WithStaticEndpoints(tokenURL, introspectURL string) RSOption {
	return func(server *resourceServer) {
		server.tokenURL = tokenURL
		server.introspectURL = introspectURL
	}
}

func Introspect(ctx context.Context, rp ResourceServer, token string) (oidc.IntrospectionResponse, error) {
	req, err := utils.FormRequest(rp.IntrospectionURL(), &oidc.IntrospectionRequest{Token: token}, encoder, nil)
	if err != nil {
		return nil, err
	}
	resp := oidc.NewIntrospectionResponse()
	if err := utils.HttpRequest(rp.HttpClient(), req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

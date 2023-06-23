package rs

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v2/pkg/client"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type ResourceServer interface {
	IntrospectionURL() string
	TokenEndpoint() string
	HttpClient() *http.Client
	AuthFn() (interface{}, error)
}

type resourceServer struct {
	issuer        string
	tokenURL      string
	introspectURL string
	httpClient    *http.Client
	authFn        func() (interface{}, error)
}

func (r *resourceServer) IntrospectionURL() string {
	return r.introspectURL
}

func (r *resourceServer) TokenEndpoint() string {
	return r.tokenURL
}

func (r *resourceServer) HttpClient() *http.Client {
	return r.httpClient
}

func (r *resourceServer) AuthFn() (interface{}, error) {
	return r.authFn()
}

func NewResourceServerClientCredentials(issuer, clientID, clientSecret string, option ...Option) (ResourceServer, error) {
	authorizer := func() (interface{}, error) {
		return httphelper.AuthorizeBasic(clientID, clientSecret), nil
	}
	return newResourceServer(issuer, authorizer, option...)
}

func NewResourceServerJWTProfile(issuer, clientID, keyID string, key []byte, options ...Option) (ResourceServer, error) {
	signer, err := client.NewSignerFromPrivateKeyByte(key, keyID)
	if err != nil {
		return nil, err
	}
	authorizer := func() (interface{}, error) {
		assertion, err := client.SignedJWTProfileAssertion(clientID, []string{issuer}, time.Hour, signer)
		if err != nil {
			return nil, err
		}
		return client.ClientAssertionFormAuthorization(assertion), nil
	}
	return newResourceServer(issuer, authorizer, options...)
}

func newResourceServer(issuer string, authorizer func() (interface{}, error), options ...Option) (*resourceServer, error) {
	rs := &resourceServer{
		issuer:     issuer,
		httpClient: httphelper.DefaultHTTPClient,
	}
	for _, optFunc := range options {
		optFunc(rs)
	}
	if rs.introspectURL == "" || rs.tokenURL == "" {
		config, err := client.Discover(rs.issuer, rs.httpClient)
		if err != nil {
			return nil, err
		}
		if rs.tokenURL == "" {
			rs.tokenURL = config.TokenEndpoint
		}
		if rs.introspectURL == "" {
			rs.introspectURL = config.IntrospectionEndpoint
		}
	}
	if rs.tokenURL == "" {
		return nil, errors.New("tokenURL is empty: please provide with either `WithStaticEndpoints` or a discovery url")
	}
	rs.authFn = authorizer
	return rs, nil
}

func NewResourceServerFromKeyFile(issuer, path string, options ...Option) (ResourceServer, error) {
	c, err := client.ConfigFromKeyFile(path)
	if err != nil {
		return nil, err
	}
	return NewResourceServerJWTProfile(issuer, c.ClientID, c.KeyID, []byte(c.Key), options...)
}

type Option func(*resourceServer)

// WithClient provides the ability to set an http client to be used for the resource server
func WithClient(client *http.Client) Option {
	return func(server *resourceServer) {
		server.httpClient = client
	}
}

// WithStaticEndpoints provides the ability to set static token and introspect URL
func WithStaticEndpoints(tokenURL, introspectURL string) Option {
	return func(server *resourceServer) {
		server.tokenURL = tokenURL
		server.introspectURL = introspectURL
	}
}

func Introspect(ctx context.Context, rp ResourceServer, token string) (*oidc.IntrospectionResponse, error) {
	if rp.IntrospectionURL() == "" {
		return nil, errors.New("resource server: introspection URL is empty")
	}
	authFn, err := rp.AuthFn()
	if err != nil {
		return nil, err
	}
	req, err := httphelper.FormRequest(rp.IntrospectionURL(), &oidc.IntrospectionRequest{Token: token}, client.Encoder, authFn)
	if err != nil {
		return nil, err
	}
	resp := new(oidc.IntrospectionResponse)
	if err := httphelper.HttpRequest(rp.HttpClient(), req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

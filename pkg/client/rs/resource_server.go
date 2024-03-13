package rs

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type ResourceServer interface {
	IntrospectionURL() string
	TokenEndpoint() string
	HttpClient() *http.Client
	AuthFn() (any, error)
}

type resourceServer struct {
	issuer        string
	tokenURL      string
	introspectURL string
	httpClient    *http.Client
	authFn        func() (any, error)
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

func (r *resourceServer) AuthFn() (any, error) {
	return r.authFn()
}

func NewResourceServerClientCredentials(ctx context.Context, issuer, clientID, clientSecret string, option ...Option) (ResourceServer, error) {
	authorizer := func() (any, error) {
		return httphelper.AuthorizeBasic(clientID, clientSecret), nil
	}
	return newResourceServer(ctx, issuer, authorizer, option...)
}

func NewResourceServerJWTProfile(ctx context.Context, issuer, clientID, keyID string, key []byte, options ...Option) (ResourceServer, error) {
	signer, err := client.NewSignerFromPrivateKeyByte(key, keyID)
	if err != nil {
		return nil, err
	}
	authorizer := func() (any, error) {
		assertion, err := client.SignedJWTProfileAssertion(clientID, []string{issuer}, time.Hour, signer)
		if err != nil {
			return nil, err
		}
		return client.ClientAssertionFormAuthorization(assertion), nil
	}
	return newResourceServer(ctx, issuer, authorizer, options...)
}

func newResourceServer(ctx context.Context, issuer string, authorizer func() (any, error), options ...Option) (*resourceServer, error) {
	rs := &resourceServer{
		issuer:     issuer,
		httpClient: httphelper.DefaultHTTPClient,
	}
	for _, optFunc := range options {
		optFunc(rs)
	}
	if rs.introspectURL == "" || rs.tokenURL == "" {
		config, err := client.Discover(ctx, rs.issuer, rs.httpClient)
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

func NewResourceServerFromKeyFile(ctx context.Context, issuer, path string, options ...Option) (ResourceServer, error) {
	c, err := client.ConfigFromKeyFile(path)
	if err != nil {
		return nil, err
	}
	return NewResourceServerJWTProfile(ctx, issuer, c.ClientID, c.KeyID, []byte(c.Key), options...)
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

// Introspect calls the [RFC7662] Token Introspection
// endpoint and returns the response in an instance of type R.
// [*oidc.IntrospectionResponse] can be used as a good example, or use a custom type if type-safe
// access to custom claims is needed.
//
// [RFC7662]: https://www.rfc-editor.org/rfc/rfc7662
func Introspect[R any](ctx context.Context, rp ResourceServer, token string) (resp R, err error) {
	ctx, span := client.Tracer.Start(ctx, "Introspect")
	defer span.End()

	if rp.IntrospectionURL() == "" {
		return resp, errors.New("resource server: introspection URL is empty")
	}
	authFn, err := rp.AuthFn()
	if err != nil {
		return resp, err
	}
	req, err := httphelper.FormRequest(ctx, rp.IntrospectionURL(), &oidc.IntrospectionRequest{Token: token}, client.Encoder, authFn)
	if err != nil {
		return resp, err
	}

	if err := httphelper.HttpRequest(rp.HttpClient(), req, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

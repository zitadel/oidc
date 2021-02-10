package rp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type ResourceServer interface {
	IntrospectionURL() string
	HttpClient() *http.Client
	AuthFn() interface{}
}

type resourceServer struct {
	issuer        string
	tokenURL      string
	introspectURL string
	httpClient    *http.Client
	authFn        interface{}
}

type jwtAccessTokenSource struct {
	clientID     string
	audience     []string
	PrivateKey   []byte
	PrivateKeyID string
}

func (j *jwtAccessTokenSource) Token() (*oauth2.Token, error) {
	iat := time.Now()
	exp := iat.Add(time.Hour)
	assertion, err := GenerateJWTProfileToken(&oidc.JWTProfileAssertion{
		PrivateKeyID: j.PrivateKeyID,
		PrivateKey:   j.PrivateKey,
		Issuer:       j.clientID,
		Subject:      j.clientID,
		Audience:     j.audience,
		Expiration:   oidc.Time(exp),
		IssuedAt:     oidc.Time(iat),
	})
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{AccessToken: assertion, TokenType: "Bearer", Expiry: exp}, nil
}

func (r *resourceServer) IntrospectionURL() string {
	return r.introspectURL
}

func (r *resourceServer) HttpClient() *http.Client {
	return r.httpClient
}

func (r *resourceServer) AuthFn() interface{} {
	return r.authFn
}

func NewResourceServerClientCredentials(issuer, clientID, clientSecret string, option RSOption) (ResourceServer, error) {
	authorizer := func(tokenURL string) func(context.Context) *http.Client {
		return (&clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
		}).Client
	}
	return newResourceServer(issuer, authorizer, option)
}
func NewResourceServerJWTProfile(issuer, clientID, keyID string, key []byte, options ...RSOption) (ResourceServer, error) {
	ts := &jwtAccessTokenSource{
		clientID:     clientID,
		PrivateKey:   key,
		PrivateKeyID: keyID,
		audience:     []string{issuer},
	}

	//authorizer := func(tokenURL string) func(context.Context) *http.Client {
	//	return func(ctx context.Context) *http.Client {
	//		return oauth2.NewClient(ctx, oauth2.ReuseTokenSource(token, ts))
	//	}
	//}
	authorizer := utils.FormAuthorization(func(values url.Values) {
		token, err := ts.Token()
		if err != nil {
			//return nil, err
		}
		values.Set("client_assertion", token.AccessToken)
	})
	return newResourceServer(issuer, authorizer, options...)
}

//
//func newResourceServer(issuer string, authorizer func(tokenURL string) func(ctx context.Context) *http.Client, options ...RSOption) (*resourceServer, error) {
//	rp := &resourceServer{
//		issuer:     issuer,
//		httpClient: utils.DefaultHTTPClient,
//	}
//	for _, optFunc := range options {
//		optFunc(rp)
//	}
//	if rp.introspectURL == "" || rp.tokenURL == "" {
//		endpoints, err := Discover(rp.issuer, rp.httpClient)
//		if err != nil {
//			return nil, err
//		}
//		rp.tokenURL = endpoints.TokenURL
//		rp.introspectURL = endpoints.IntrospectURL
//	}
//	if rp.introspectURL == "" || rp.tokenURL == "" {
//		return nil, errors.New("introspectURL and/or tokenURL is empty: please provide with either `WithStaticEndpoints` or a discovery url")
//	}
//	//rp.httpClient = authorizer(rp.tokenURL)(context.WithValue(context.Background(), oauth2.HTTPClient, rp.HttpClient()))
//	return rp, nil
//}
func newResourceServer(issuer string, authorizer interface{}, options ...RSOption) (*resourceServer, error) {
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
	//rp.httpClient = authorizer(rp.tokenURL)(context.WithValue(context.Background(), oauth2.HTTPClient, rp.HttpClient()))
	rp.authFn = authorizer
	return rp, nil
}

func NewResourceServerFromKeyFile(path string, options ...RSOption) (ResourceServer, error) {
	c, err := ConfigFromKeyFile(path)
	if err != nil {
		return nil, err
	}
	c.Issuer = "http://localhost:50002/oauth/v2"
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
	req, err := utils.FormRequest(rp.IntrospectionURL(), &oidc.IntrospectionRequest{Token: token}, encoder, rp.AuthFn())
	if err != nil {
		return nil, err
	}
	resp := oidc.NewIntrospectionResponse()
	if err := utils.HttpRequest(rp.HttpClient(), req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

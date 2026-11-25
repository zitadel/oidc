package profile

import (
	"context"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v4/pkg/client"
	"github.com/zitadel/oidc/v4/pkg/oidc"
)

type TokenSource interface {
	oauth2.TokenSource
	TokenCtx(context.Context) (*oauth2.Token, error)
}

// jwtProfileTokenSource implement the oauth2.TokenSource
// it will request a token using the OAuth2 JWT Profile Grant
// therefore sending an `assertion` by signing a JWT with the provided private key
type jwtProfileTokenSource struct {
	clientID      string
	audience      []string
	signer        jose.Signer
	scopes        []string
	httpClient    *http.Client
	tokenEndpoint string
}

// NewJWTProfileTokenSource returns an implementation of oauth2.TokenSource
// It will request a token using the OAuth2 JWT Profile Grant,
// therefore sending an `assertion` by singing a JWT with the provided private key.
//
// The passed context is only used for the call to the Discover endpoint.
func NewJWTProfileTokenSource(ctx context.Context, issuer, clientID, keyID string, key []byte, scopes []string, options ...func(source *jwtProfileTokenSource)) (TokenSource, error) {
	signer, err := client.NewSignerFromPrivateKeyByte(key, keyID)
	if err != nil {
		return nil, err
	}
	source := &jwtProfileTokenSource{
		clientID:   clientID,
		audience:   []string{issuer},
		signer:     signer,
		scopes:     scopes,
		httpClient: http.DefaultClient,
	}
	for _, opt := range options {
		opt(source)
	}
	if source.tokenEndpoint == "" {
		config, err := client.Discover(ctx, issuer, source.httpClient)
		if err != nil {
			return nil, err
		}
		source.tokenEndpoint = config.TokenEndpoint
	}
	return source, nil
}

func WithHTTPClient(client *http.Client) func(source *jwtProfileTokenSource) {
	return func(source *jwtProfileTokenSource) {
		source.httpClient = client
	}
}

func WithStaticTokenEndpoint(issuer, tokenEndpoint string) func(source *jwtProfileTokenSource) {
	return func(source *jwtProfileTokenSource) {
		source.tokenEndpoint = tokenEndpoint
	}
}

func (j *jwtProfileTokenSource) TokenEndpoint() string {
	return j.tokenEndpoint
}

func (j *jwtProfileTokenSource) HttpClient() *http.Client {
	return j.httpClient
}

func (j *jwtProfileTokenSource) Token() (*oauth2.Token, error) {
	return j.TokenCtx(context.Background())
}

func (j *jwtProfileTokenSource) TokenCtx(ctx context.Context) (*oauth2.Token, error) {
	assertion, err := client.SignedJWTProfileAssertion(j.clientID, j.audience, time.Hour, j.signer)
	if err != nil {
		return nil, err
	}
	return client.JWTProfileExchange(ctx, oidc.NewJWTProfileGrantRequest(assertion, j.scopes...), j)
}

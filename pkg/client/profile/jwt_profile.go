package profile

import (
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/client"
	"github.com/caos/oidc/pkg/oidc"
)

//jwtProfileTokenSource implement the oauth2.TokenSource
//it will request a token using the OAuth2 JWT Profile Grant
//therefore sending an `assertion` by singing a JWT with the provided private key
type jwtProfileTokenSource struct {
	clientID      string
	audience      []string
	signer        jose.Signer
	scopes        []string
	httpClient    *http.Client
	tokenEndpoint string
}

func NewJWTProfileTokenSourceFromKeyFile(issuer string, data []byte, scopes []string, options ...func(source *jwtProfileTokenSource)) (oauth2.TokenSource, error) {
	keyData, err := client.ConfigFromKeyFileData(data)
	if err != nil {
		return nil, err
	}
	return NewJWTProfileTokenSource(issuer, keyData.UserID, keyData.KeyID, []byte(keyData.Key), scopes, options...)
}

func NewJWTProfileTokenSource(issuer, clientID, keyID string, key []byte, scopes []string, options ...func(source *jwtProfileTokenSource)) (oauth2.TokenSource, error) {
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
		config, err := client.Discover(issuer, source.httpClient)
		if err != nil {
			return nil, err
		}
		source.tokenEndpoint = config.TokenEndpoint
	}
	return source, nil
}

func WithHTTPClient(client *http.Client) func(*jwtProfileTokenSource) {
	return func(source *jwtProfileTokenSource) {
		source.httpClient = client
	}
}

func WithStaticTokenEndpoint(issuer, tokenEndpoint string) func(*jwtProfileTokenSource) {
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
	assertion, err := client.SignedJWTProfileAssertion(j.clientID, j.audience, time.Hour, j.signer)
	if err != nil {
		return nil, err
	}
	return client.JWTProfileExchange(nil, oidc.NewJWTProfileGrantRequest(assertion, j.scopes...), j)
}

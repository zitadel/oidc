package client

import (
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/pkg/crypto"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

var (
	Encoder = func() httphelper.Encoder {
		e := schema.NewEncoder()
		e.RegisterEncoder(oidc.SpaceDelimitedArray{}, func(value reflect.Value) string {
			return value.Interface().(oidc.SpaceDelimitedArray).Encode()
		})
		return e
	}()
)

//Discover calls the discovery endpoint of the provided issuer and returns its configuration
//It accepts an optional argument "wellknownUrl" which can be used to overide the dicovery endpoint url
func Discover(issuer string, httpClient *http.Client, wellKnownUrl ...string) (*oidc.DiscoveryConfiguration, error) {

	wellKnown := strings.TrimSuffix(issuer, "/") + oidc.DiscoveryEndpoint
	if len(wellKnownUrl) == 1 && wellKnownUrl[0] != "" {
		wellKnown = wellKnownUrl[0]
	}
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	discoveryConfig := new(oidc.DiscoveryConfiguration)
	err = httphelper.HttpRequest(httpClient, req, &discoveryConfig)
	if err != nil {
		return nil, err
	}
	if discoveryConfig.Issuer != issuer {
		return nil, oidc.ErrIssuerInvalid
	}
	return discoveryConfig, nil
}

type TokenEndpointCaller interface {
	TokenEndpoint() string
	HttpClient() *http.Client
}

func CallTokenEndpoint(request interface{}, caller TokenEndpointCaller) (newToken *oauth2.Token, err error) {
	return callTokenEndpoint(request, nil, caller)
}

func callTokenEndpoint(request interface{}, authFn interface{}, caller TokenEndpointCaller) (newToken *oauth2.Token, err error) {
	req, err := httphelper.FormRequest(caller.TokenEndpoint(), request, Encoder, authFn)
	if err != nil {
		return nil, err
	}
	tokenRes := new(oidc.AccessTokenResponse)
	if err := httphelper.HttpRequest(caller.HttpClient(), req, &tokenRes); err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken:  tokenRes.AccessToken,
		TokenType:    tokenRes.TokenType,
		RefreshToken: tokenRes.RefreshToken,
		Expiry:       time.Now().UTC().Add(time.Duration(tokenRes.ExpiresIn) * time.Second),
	}, nil
}

func NewSignerFromPrivateKeyByte(key []byte, keyID string) (jose.Signer, error) {
	privateKey, err := crypto.BytesToPrivateKey(key)
	if err != nil {
		return nil, err
	}
	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       &jose.JSONWebKey{Key: privateKey, KeyID: keyID},
	}
	return jose.NewSigner(signingKey, &jose.SignerOptions{})
}

func SignedJWTProfileAssertion(clientID string, audience []string, expiration time.Duration, signer jose.Signer) (string, error) {
	iat := time.Now()
	exp := iat.Add(expiration)
	return crypto.Sign(&oidc.JWTTokenRequest{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  audience,
		ExpiresAt: oidc.Time(exp),
		IssuedAt:  oidc.Time(iat),
	}, signer)
}

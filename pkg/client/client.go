package client

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/v2/pkg/crypto"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

var Encoder = func() httphelper.Encoder {
	e := schema.NewEncoder()
	e.RegisterEncoder(oidc.SpaceDelimitedArray{}, func(value reflect.Value) string {
		return value.Interface().(oidc.SpaceDelimitedArray).Encode()
	})
	return e
}()

// Discover calls the discovery endpoint of the provided issuer and returns its configuration
// It accepts an optional argument "wellknownUrl" which can be used to overide the dicovery endpoint url
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

type EndSessionCaller interface {
	GetEndSessionEndpoint() string
	HttpClient() *http.Client
}

func CallEndSessionEndpoint(request interface{}, authFn interface{}, caller EndSessionCaller) (*url.URL, error) {
	req, err := httphelper.FormRequest(caller.GetEndSessionEndpoint(), request, Encoder, authFn)
	if err != nil {
		return nil, err
	}
	client := caller.HttpClient()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("EndSession failure, %d status code: %s", resp.StatusCode, string(body))
	}
	location, err := resp.Location()
	if err != nil {
		if errors.Is(err, http.ErrNoLocation) {
			return nil, nil
		}
		return nil, err
	}
	return location, nil
}

type RevokeCaller interface {
	GetRevokeEndpoint() string
	HttpClient() *http.Client
}

type RevokeRequest struct {
	Token         string `schema:"token"`
	TokenTypeHint string `schema:"token_type_hint"`
	ClientID      string `schema:"client_id"`
	ClientSecret  string `schema:"client_secret"`
}

func CallRevokeEndpoint(request interface{}, authFn interface{}, caller RevokeCaller) error {
	req, err := httphelper.FormRequest(caller.GetRevokeEndpoint(), request, Encoder, authFn)
	if err != nil {
		return err
	}
	client := caller.HttpClient()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// According to RFC7009 in section 2.2:
	// "The content of the response body is ignored by the client as all
	// necessary information is conveyed in the response code."
	if resp.StatusCode != 200 {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			return fmt.Errorf("revoke returned status %d and text: %s", resp.StatusCode, string(body))
		} else {
			return fmt.Errorf("revoke returned status %d", resp.StatusCode)
		}
	}
	return nil
}

func CallTokenExchangeEndpoint(request interface{}, authFn interface{}, caller TokenEndpointCaller) (resp *oidc.TokenExchangeResponse, err error) {
	req, err := httphelper.FormRequest(caller.TokenEndpoint(), request, Encoder, authFn)
	if err != nil {
		return nil, err
	}
	tokenRes := new(oidc.TokenExchangeResponse)
	if err := httphelper.HttpRequest(caller.HttpClient(), req, &tokenRes); err != nil {
		return nil, err
	}
	return tokenRes, nil
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

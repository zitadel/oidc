package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/logging"
	"go.opentelemetry.io/otel"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/pkg/crypto"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	Encoder = httphelper.Encoder(oidc.NewEncoder())
	Tracer  = otel.Tracer("github.com/zitadel/oidc/pkg/client")
)

// Discover calls the discovery endpoint of the provided issuer and returns its configuration
// It accepts an optional argument "wellknownUrl" which can be used to overide the dicovery endpoint url
func Discover(ctx context.Context, issuer string, httpClient *http.Client, wellKnownUrl ...string) (*oidc.DiscoveryConfiguration, error) {
	ctx, span := Tracer.Start(ctx, "Discover")
	defer span.End()

	wellKnown := strings.TrimSuffix(issuer, "/") + oidc.DiscoveryEndpoint
	if len(wellKnownUrl) == 1 && wellKnownUrl[0] != "" {
		wellKnown = wellKnownUrl[0]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	discoveryConfig := new(oidc.DiscoveryConfiguration)
	err = httphelper.HttpRequest(httpClient, req, &discoveryConfig)
	if err != nil {
		return nil, err
	}
	if logger, ok := logging.FromContext(ctx); ok {
		logger.Debug("discover", "config", discoveryConfig)
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

func CallTokenEndpoint(ctx context.Context, request any, caller TokenEndpointCaller) (newToken *oauth2.Token, err error) {
	return callTokenEndpoint(ctx, request, nil, caller)
}

func callTokenEndpoint(ctx context.Context, request any, authFn any, caller TokenEndpointCaller) (newToken *oauth2.Token, err error) {
	ctx, span := Tracer.Start(ctx, "callTokenEndpoint")
	defer span.End()

	req, err := httphelper.FormRequest(ctx, caller.TokenEndpoint(), request, Encoder, authFn)
	if err != nil {
		return nil, err
	}
	tokenRes := new(oidc.AccessTokenResponse)
	if err := httphelper.HttpRequest(caller.HttpClient(), req, &tokenRes); err != nil {
		return nil, err
	}
	token := &oauth2.Token{
		AccessToken:  tokenRes.AccessToken,
		TokenType:    tokenRes.TokenType,
		RefreshToken: tokenRes.RefreshToken,
		Expiry:       time.Now().UTC().Add(time.Duration(tokenRes.ExpiresIn) * time.Second),
	}
	if tokenRes.IDToken != "" {
		token = token.WithExtra(map[string]any{
			"id_token": tokenRes.IDToken,
		})
	}
	return token, nil
}

type EndSessionCaller interface {
	GetEndSessionEndpoint() string
	HttpClient() *http.Client
}

func CallEndSessionEndpoint(ctx context.Context, request any, authFn any, caller EndSessionCaller) (*url.URL, error) {
	ctx, span := Tracer.Start(ctx, "CallEndSessionEndpoint")
	defer span.End()

	endpoint := caller.GetEndSessionEndpoint()
	if endpoint == "" {
		return nil, fmt.Errorf("end session %w", ErrEndpointNotSet)
	}

	req, err := httphelper.FormRequest(ctx, endpoint, request, Encoder, authFn)
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

func CallRevokeEndpoint(ctx context.Context, request any, authFn any, caller RevokeCaller) error {
	ctx, span := Tracer.Start(ctx, "CallRevokeEndpoint")
	defer span.End()

	endpoint := caller.GetRevokeEndpoint()
	if endpoint == "" {
		return fmt.Errorf("revoke %w", ErrEndpointNotSet)
	}

	req, err := httphelper.FormRequest(ctx, endpoint, request, Encoder, authFn)
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

func CallTokenExchangeEndpoint(ctx context.Context, request any, authFn any, caller TokenEndpointCaller) (resp *oidc.TokenExchangeResponse, err error) {
	ctx, span := Tracer.Start(ctx, "CallTokenExchangeEndpoint")
	defer span.End()

	req, err := httphelper.FormRequest(ctx, caller.TokenEndpoint(), request, Encoder, authFn)
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
	privateKey, algorithm, err := crypto.BytesToPrivateKey(key)
	if err != nil {
		return nil, err
	}
	signingKey := jose.SigningKey{
		Algorithm: algorithm,
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
		ExpiresAt: oidc.FromTime(exp),
		IssuedAt:  oidc.FromTime(iat),
	}, signer)
}

type DeviceAuthorizationCaller interface {
	GetDeviceAuthorizationEndpoint() string
	HttpClient() *http.Client
}

func CallDeviceAuthorizationEndpoint(ctx context.Context, request *oidc.ClientCredentialsRequest, caller DeviceAuthorizationCaller, authFn any) (*oidc.DeviceAuthorizationResponse, error) {
	ctx, span := Tracer.Start(ctx, "CallDeviceAuthorizationEndpoint")
	defer span.End()

	endpoint := caller.GetDeviceAuthorizationEndpoint()
	if endpoint == "" {
		return nil, fmt.Errorf("device authorization %w", ErrEndpointNotSet)
	}

	req, err := httphelper.FormRequest(ctx, endpoint, request, Encoder, authFn)
	if err != nil {
		return nil, err
	}
	if request.ClientSecret != "" {
		req.SetBasicAuth(request.ClientID, request.ClientSecret)
	}

	resp := new(oidc.DeviceAuthorizationResponse)
	if err := httphelper.HttpRequest(caller.HttpClient(), req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type DeviceAccessTokenRequest struct {
	*oidc.ClientCredentialsRequest
	oidc.DeviceAccessTokenRequest
}

func CallDeviceAccessTokenEndpoint(ctx context.Context, request *DeviceAccessTokenRequest, caller TokenEndpointCaller) (*oidc.AccessTokenResponse, error) {
	ctx, span := Tracer.Start(ctx, "CallDeviceAccessTokenEndpoint")
	defer span.End()

	req, err := httphelper.FormRequest(ctx, caller.TokenEndpoint(), request, Encoder, nil)
	if err != nil {
		return nil, err
	}
	if request.ClientSecret != "" {
		req.SetBasicAuth(request.ClientID, request.ClientSecret)
	}

	resp := new(oidc.AccessTokenResponse)
	if err := httphelper.HttpRequest(caller.HttpClient(), req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func PollDeviceAccessTokenEndpoint(ctx context.Context, interval time.Duration, request *DeviceAccessTokenRequest, caller TokenEndpointCaller) (*oidc.AccessTokenResponse, error) {
	ctx, span := Tracer.Start(ctx, "PollDeviceAccessTokenEndpoint")
	defer span.End()

	for {
		timer := time.After(interval)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer:
		}

		ctx, cancel := context.WithTimeout(ctx, interval)
		defer cancel()

		resp, err := CallDeviceAccessTokenEndpoint(ctx, request, caller)
		if err == nil {
			return resp, nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			interval += 5 * time.Second
		}
		var target *oidc.Error
		if !errors.As(err, &target) {
			return nil, err
		}
		switch target.ErrorType {
		case oidc.AuthorizationPending:
			continue
		case oidc.SlowDown:
			interval += 5 * time.Second
			continue
		default:
			return nil, err
		}
	}
}

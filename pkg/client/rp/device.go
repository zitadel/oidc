package rp

import (
	"context"
	"fmt"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func newDeviceClientCredentialsRequest(scopes []string, rp RelyingParty) (*oidc.ClientCredentialsRequest, error) {
	confg := rp.OAuthConfig()
	req := &oidc.ClientCredentialsRequest{
		Scope:        scopes,
		ClientID:     confg.ClientID,
		ClientSecret: confg.ClientSecret,
	}

	if signer := rp.Signer(); signer != nil {
		assertion, err := client.SignedJWTProfileAssertion(rp.OAuthConfig().ClientID, []string{rp.Issuer()}, time.Hour, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to build assertion: %w", err)
		}
		req.ClientAssertion = assertion
		req.ClientAssertionType = oidc.ClientAssertionTypeJWTAssertion
	}

	return req, nil
}

// DeviceAuthorization starts a new Device Authorization flow as defined
// in RFC 8628, section 3.1 and 3.2:
// https://www.rfc-editor.org/rfc/rfc8628#section-3.1
func DeviceAuthorization(ctx context.Context, scopes []string, rp RelyingParty, authFn any) (*oidc.DeviceAuthorizationResponse, error) {
	ctx, span := client.Tracer.Start(ctx, "DeviceAuthorization")
	defer span.End()

	ctx = logCtxWithRPData(ctx, rp, "function", "DeviceAuthorization")
	req, err := newDeviceClientCredentialsRequest(scopes, rp)
	if err != nil {
		return nil, err
	}

	return client.CallDeviceAuthorizationEndpoint(ctx, req, rp, authFn)
}

// DeviceAccessToken attempts to obtain tokens from a Device Authorization,
// by means of polling as defined in RFC, section 3.3 and 3.4:
// https://www.rfc-editor.org/rfc/rfc8628#section-3.4
func DeviceAccessToken(ctx context.Context, deviceCode string, interval time.Duration, rp RelyingParty) (resp *oidc.AccessTokenResponse, err error) {
	ctx, span := client.Tracer.Start(ctx, "DeviceAccessToken")
	defer span.End()

	ctx = logCtxWithRPData(ctx, rp, "function", "DeviceAccessToken")
	req := &client.DeviceAccessTokenRequest{
		DeviceAccessTokenRequest: oidc.DeviceAccessTokenRequest{
			GrantType:  oidc.GrantTypeDeviceCode,
			DeviceCode: deviceCode,
		},
	}

	req.ClientCredentialsRequest, err = newDeviceClientCredentialsRequest(nil, rp)
	if err != nil {
		return nil, err
	}

	return client.PollDeviceAccessTokenEndpoint(ctx, interval, req, tokenEndpointCaller{rp})
}

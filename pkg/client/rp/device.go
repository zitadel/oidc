package rp

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func newDeviceClientCredentialsRequest(scopes []string, rp RelyingParty) (*oidc.ClientCredentialsRequest, error) {
	config := rp.OAuthConfig()
	req := &oidc.ClientCredentialsRequest{
		Scope:        scopes,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
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
//
// When the RelyingParty is configured with [WithKeyBinding], the `bound_key`
// scope and the `dpop_jkt` parameter are added.
func DeviceAuthorization(ctx context.Context, scopes []string, rp RelyingParty, authFn any) (*oidc.DeviceAuthorizationResponse, error) {
	ctx, span := client.Tracer.Start(ctx, "DeviceAuthorization")
	defer span.End()

	configured, bound := keyBindingRP(rp)
	if bound && !slices.Contains(scopes, oidc.ScopeBoundKey) {
		scopes = append(slices.Clone(scopes), oidc.ScopeBoundKey)
	}

	req, err := newDeviceClientCredentialsRequest(scopes, rp)
	if err != nil {
		return nil, err
	}
	if !bound {
		return client.CallDeviceAuthorizationEndpoint(ctx, req, rp, authFn)
	}
	return client.CallDeviceAuthorizationEndpointWithBoundKey(ctx, &client.BoundKeyDeviceAuthorizationRequest{
		ClientCredentialsRequest: req,
		DPoPJKT:                  configured.KeyBindingThumbprint(),
	}, rp, authFn)
}

// DeviceAccessToken attempts to obtain tokens from a Device Authorization,
// by means of polling as defined in RFC, section 3.3 and 3.4:
// https://www.rfc-editor.org/rfc/rfc8628#section-3.4
//
// When the RelyingParty is configured with [WithKeyBinding], each poll carries a
// DPoP proof bound to deviceCode.
func DeviceAccessToken(ctx context.Context, deviceCode string, interval time.Duration, rp RelyingParty) (resp *oidc.AccessTokenResponse, err error) {
	ctx, span := client.Tracer.Start(ctx, "DeviceAccessToken")
	defer span.End()

	req := &client.DeviceAccessTokenRequest{
		DeviceAccessTokenRequest: oidc.DeviceAccessTokenRequest{
			GrantType:  oidc.GrantTypeDeviceCode,
			DeviceCode: deviceCode,
		},
		ClientCredentialsRequest: &oidc.ClientCredentialsRequest{},
	}

	var authFn httphelper.RequestAuthorization

	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
	// The client MUST NOT use more than one authentication method in each request.
	switch rp.OAuthConfig().Endpoint.AuthStyle {
	case oauth2.AuthStyleInHeader:
		authFn = httphelper.AuthorizeBasic(rp.OAuthConfig().ClientID, rp.OAuthConfig().ClientSecret)
	default:
		if signer := rp.Signer(); signer != nil {
			assertion, err := client.SignedJWTProfileAssertion(rp.OAuthConfig().ClientID, []string{rp.Issuer()}, time.Hour, signer)
			if err != nil {
				return nil, fmt.Errorf("failed to build assertion: %w", err)
			}
			req.ClientAssertion = assertion
			req.ClientAssertionType = oidc.ClientAssertionTypeJWTAssertion
		} else {
			req.ClientID = rp.OAuthConfig().ClientID
			req.ClientSecret = rp.OAuthConfig().ClientSecret
		}

	}

	caller := tokenEndpointCaller{RelyingParty: rp}
	configured, bound := keyBindingRP(rp)
	if bound {
		// The proof is over the device code (c_s256)
		caller.httpClient = keyBindingHTTPClient(rp.HttpClient(), configured, deviceCode, rp.OAuthConfig().Endpoint.TokenURL)
	}

	resp, err = client.PollDeviceAccessTokenEndpointWithAuthFn(ctx, interval, req, caller, authFn)
	if err != nil {
		return nil, err
	}
	if bound {
		if err := verifyDeviceKeyBinding(ctx, resp, rp, configured); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// verifyDeviceKeyBinding checks that the ID Token returned by the device token
// endpoint really is bound to the RP's binding key.
func verifyDeviceKeyBinding(ctx context.Context, resp *oidc.AccessTokenResponse, rp RelyingParty, configured KeyBindingRelyingParty) error {
	if resp.IDToken == "" {
		return fmt.Errorf("%w: no id_token returned for a bound_key request", ErrKeyBindingIDToken)
	}
	idToken, err := VerifyIDToken[*oidc.IDTokenClaims](ctx, resp.IDToken, rp.IDTokenVerifier())
	if err != nil {
		return err
	}
	return verifyKeyBindingIDToken(resp.IDToken, idToken.GetSignatureAlgorithm(), configured.KeyBindingThumbprint())
}

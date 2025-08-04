package rp

import (
	"context"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// VerifyTokens implement the Token Response Validation as defined in OIDC specification
// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
func VerifyTokens[C oidc.IDClaims](ctx context.Context, accessToken, idToken string, v *IDTokenVerifier) (claims C, err error) {
	ctx, span := client.Tracer.Start(ctx, "VerifyTokens")
	defer span.End()

	var nilClaims C

	claims, err = VerifyIDToken[C](ctx, idToken, v)
	if err != nil {
		return nilClaims, err
	}
	if err := VerifyAccessToken(accessToken, claims.GetAccessTokenHash(), claims.GetSignatureAlgorithm()); err != nil {
		return nilClaims, err
	}
	return claims, nil
}

// VerifyIDToken validates the id token according to
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func VerifyIDToken[C oidc.Claims](ctx context.Context, token string, v *IDTokenVerifier) (claims C, err error) {
	ctx, span := client.Tracer.Start(ctx, "VerifyIDToken")
	defer span.End()

	var nilClaims C

	decrypted, err := oidc.DecryptToken(token)
	if err != nil {
		return nilClaims, err
	}
	payload, err := oidc.ParseToken(decrypted, &claims)
	if err != nil {
		return nilClaims, err
	}

	if err := oidc.CheckSubject(claims); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckIssuer(claims, v.Issuer); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAudience(claims, v.ClientID); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAZPVerifier(claims, v.AZP); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs, v.KeySet); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckExpiration(claims, v.Offset); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckIssuedAt(claims, v.MaxAgeIAT, v.Offset); err != nil {
		return nilClaims, err
	}

	if v.Nonce != nil {
		if err = oidc.CheckNonce(claims, v.Nonce(ctx)); err != nil {
			return nilClaims, err
		}
	}

	if err = oidc.CheckAuthorizationContextClassReference(claims, v.ACR); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAuthTime(claims, v.MaxAge); err != nil {
		return nilClaims, err
	}

	return claims, nil
}

type IDTokenVerifier oidc.Verifier

// VerifyAccessToken validates the access token according to
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
func VerifyAccessToken(accessToken, atHash string, sigAlgorithm jose.SignatureAlgorithm) error {
	if atHash == "" {
		return nil
	}

	actual, err := oidc.ClaimHash(accessToken, sigAlgorithm)
	if err != nil {
		return err
	}
	if actual != atHash {
		return oidc.ErrAtHash
	}
	return nil
}

// NewIDTokenVerifier returns a oidc.Verifier suitable for ID token verification.
func NewIDTokenVerifier(issuer, clientID string, keySet oidc.KeySet, options ...VerifierOption) *IDTokenVerifier {
	v := &IDTokenVerifier{
		Issuer:   issuer,
		ClientID: clientID,
		KeySet:   keySet,
		Offset:   time.Second,
		Nonce: func(_ context.Context) string {
			return ""
		},
		AZP: oidc.DefaultAZPVerifier(clientID),
	}

	for _, opts := range options {
		opts(v)
	}

	return v
}

// VerifierOption is the type for providing dynamic options to the IDTokenVerifier
type VerifierOption func(*IDTokenVerifier)

// WithIssuedAtOffset mitigates the risk of iat to be in the future
// because of clock skews with the ability to add an offset to the current time
func WithIssuedAtOffset(offset time.Duration) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.Offset = offset
	}
}

// WithIssuedAtMaxAge provides the ability to define the maximum duration between iat and now
func WithIssuedAtMaxAge(maxAge time.Duration) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.MaxAgeIAT = maxAge
	}
}

// WithNonce sets the function to check the nonce
func WithNonce(nonce func(context.Context) string) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.Nonce = nonce
	}
}

// WithACRVerifier sets the verifier for the acr claim
func WithACRVerifier(verifier oidc.ACRVerifier) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.ACR = verifier
	}
}

// WithAZPVerifier sets the verifier for the azp claim
func WithAZPVerifier(verifier oidc.AZPVerifier) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.AZP = verifier
	}
}

// WithAuthTimeMaxAge provides the ability to define the maximum duration between auth_time and now
func WithAuthTimeMaxAge(maxAge time.Duration) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.MaxAge = maxAge
	}
}

// WithSupportedSigningAlgorithms overwrites the default RS256 signing algorithm
func WithSupportedSigningAlgorithms(algs ...string) VerifierOption {
	return func(v *IDTokenVerifier) {
		v.SupportedSignAlgs = algs
	}
}

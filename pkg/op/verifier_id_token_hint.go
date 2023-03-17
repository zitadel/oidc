package op

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type IDTokenHintVerifierOpt func(*oidc.Verifier)

func WithSupportedIDTokenHintSigningAlgorithms(algs ...string) IDTokenHintVerifierOpt {
	return func(verifier *oidc.Verifier) {
		verifier.SupportedSignAlgs = algs
	}
}

func NewIDTokenHintVerifier(issuer string, keySet oidc.KeySet, opts ...IDTokenHintVerifierOpt) *oidc.Verifier {
	verifier := &oidc.Verifier{
		Issuer: issuer,
		KeySet: keySet,
	}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

// VerifyIDTokenHint validates the id token according to
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func VerifyIDTokenHint[C oidc.Claims](ctx context.Context, token string, v *oidc.Verifier) (claims C, err error) {
	var nilClaims C

	decrypted, err := oidc.DecryptToken(token)
	if err != nil {
		return nilClaims, err
	}
	payload, err := oidc.ParseToken(decrypted, &claims)
	if err != nil {
		return nilClaims, err
	}

	if err := oidc.CheckIssuer(claims, v.Issuer); err != nil {
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

	if err = oidc.CheckAuthorizationContextClassReference(claims, v.ACR); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAuthTime(claims, v.MaxAge); err != nil {
		return nilClaims, err
	}
	return claims, nil
}

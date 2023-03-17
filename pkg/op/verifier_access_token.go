package op

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AccessTokenVerifierOpt func(*oidc.Verifier)

func WithSupportedAccessTokenSigningAlgorithms(algs ...string) AccessTokenVerifierOpt {
	return func(verifier *oidc.Verifier) {
		verifier.SupportedSignAlgs = algs
	}
}

// NewAccessTokenVerifier returns a oidc.Verifier suitable for access token verification.
func NewAccessTokenVerifier(issuer string, keySet oidc.KeySet, opts ...AccessTokenVerifierOpt) *oidc.Verifier {
	verifier := &oidc.Verifier{
		Issuer: issuer,
		KeySet: keySet,
	}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

// VerifyAccessToken validates the access token (issuer, signature and expiration).
func VerifyAccessToken[C oidc.Claims](ctx context.Context, token string, v *oidc.Verifier) (claims C, err error) {
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

	return claims, nil
}

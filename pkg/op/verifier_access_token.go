package op

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AccessTokenVerifier oidc.Verifier

type AccessTokenVerifierOpt func(*AccessTokenVerifier)

func WithSupportedAccessTokenSigningAlgorithms(algs ...string) AccessTokenVerifierOpt {
	return func(verifier *AccessTokenVerifier) {
		verifier.SupportedSignAlgs = algs
	}
}

// NewAccessTokenVerifier returns a AccessTokenVerifier suitable for access token verification.
func NewAccessTokenVerifier(issuer string, keySet oidc.KeySet, opts ...AccessTokenVerifierOpt) *AccessTokenVerifier {
	verifier := &AccessTokenVerifier{
		Issuer: issuer,
		KeySet: keySet,
	}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

// VerifyAccessToken validates the access token (issuer, signature and expiration).
func VerifyAccessToken[C oidc.Claims](ctx context.Context, token string, v *AccessTokenVerifier) (claims C, err error) {
	ctx, span := tracer.Start(ctx, "VerifyAccessToken")
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

package op

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type IDTokenHintVerifier oidc.Verifier

type IDTokenHintVerifierOpt func(*IDTokenHintVerifier)

func WithSupportedIDTokenHintSigningAlgorithms(algs ...string) IDTokenHintVerifierOpt {
	return func(verifier *IDTokenHintVerifier) {
		verifier.SupportedSignAlgs = algs
	}
}

func NewIDTokenHintVerifier(issuer string, keySet oidc.KeySet, opts ...IDTokenHintVerifierOpt) *IDTokenHintVerifier {
	verifier := &IDTokenHintVerifier{
		Issuer: issuer,
		KeySet: keySet,
	}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

type IDTokenHintExpiredError struct {
	error
}

func (e IDTokenHintExpiredError) Unwrap() error {
	return e.error
}

func (e IDTokenHintExpiredError) Is(err error) bool {
	return errors.Is(err, e.error)
}

// VerifyIDTokenHint validates the id token according to
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.
// In case of an expired token both the Claims and first encountered expiry related error
// is returned of type [IDTokenHintExpiredError]. In that case the caller can choose to still
// trust the token for cases like logout, as signature and other verifications succeeded.
func VerifyIDTokenHint[C oidc.Claims](ctx context.Context, token string, v *IDTokenHintVerifier) (claims C, err error) {
	ctx, span := tracer.Start(ctx, "VerifyIDTokenHint")
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

	if err = oidc.CheckAuthorizationContextClassReference(claims, v.ACR); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckExpiration(claims, v.Offset); err != nil {
		return claims, IDTokenHintExpiredError{err}
	}

	if err = oidc.CheckIssuedAt(claims, v.MaxAgeIAT, v.Offset); err != nil {
		return claims, IDTokenHintExpiredError{err}
	}

	if err = oidc.CheckAuthTime(claims, v.MaxAge); err != nil {
		return claims, IDTokenHintExpiredError{err}
	}
	return claims, nil
}

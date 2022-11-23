package op

import (
	"context"
	"time"

	"github.com/zitadel/oidc/pkg/oidc"
)

type IDTokenHintVerifier interface {
	oidc.Verifier
	SupportedSignAlgs() []string
	KeySet() oidc.KeySet
	ACR() oidc.ACRVerifier
	MaxAge() time.Duration
}

type idTokenHintVerifier struct {
	issuer            string
	maxAgeIAT         time.Duration
	offset            time.Duration
	supportedSignAlgs []string
	maxAge            time.Duration
	acr               oidc.ACRVerifier
	keySet            oidc.KeySet
}

func (i *idTokenHintVerifier) Issuer() string {
	return i.issuer
}

func (i *idTokenHintVerifier) MaxAgeIAT() time.Duration {
	return i.maxAgeIAT
}

func (i *idTokenHintVerifier) Offset() time.Duration {
	return i.offset
}

func (i *idTokenHintVerifier) SupportedSignAlgs() []string {
	return i.supportedSignAlgs
}

func (i *idTokenHintVerifier) KeySet() oidc.KeySet {
	return i.keySet
}

func (i *idTokenHintVerifier) ACR() oidc.ACRVerifier {
	return i.acr
}

func (i *idTokenHintVerifier) MaxAge() time.Duration {
	return i.maxAge
}

type IDTokenHintVerifierOpt func(*idTokenHintVerifier)

func WithSupportedIDTokenHintSigningAlgorithms(algs ...string) IDTokenHintVerifierOpt {
	return func(verifier *idTokenHintVerifier) {
		verifier.supportedSignAlgs = algs
	}
}

func NewIDTokenHintVerifier(issuer string, keySet oidc.KeySet, opts ...IDTokenHintVerifierOpt) IDTokenHintVerifier {
	verifier := &idTokenHintVerifier{
		issuer: issuer,
		keySet: keySet,
	}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

// VerifyIDTokenHint validates the id token according to
//https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func VerifyIDTokenHint(ctx context.Context, token string, v IDTokenHintVerifier) (oidc.IDTokenClaims, error) {
	claims := oidc.EmptyIDTokenClaims()

	decrypted, err := oidc.DecryptToken(token)
	if err != nil {
		return nil, err
	}
	payload, err := oidc.ParseToken(decrypted, claims)
	if err != nil {
		return nil, err
	}

	if err := oidc.CheckIssuer(claims, v.Issuer()); err != nil {
		return nil, err
	}

	if err = oidc.CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs(), v.KeySet()); err != nil {
		return nil, err
	}

	if err = oidc.CheckExpiration(claims, v.Offset()); err != nil {
		return nil, err
	}

	if err = oidc.CheckIssuedAt(claims, v.MaxAgeIAT(), v.Offset()); err != nil {
		return nil, err
	}

	if err = oidc.CheckAuthorizationContextClassReference(claims, v.ACR()); err != nil {
		return nil, err
	}

	if err = oidc.CheckAuthTime(claims, v.MaxAge()); err != nil {
		return nil, err
	}
	return claims, nil
}

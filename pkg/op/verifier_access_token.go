package op

import (
	"context"
	"time"

	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type AccessTokenVerifier interface {
	oidc.Verifier
	SupportedSignAlgs() []string
	KeySet() oidc.KeySet
}

type accessTokenVerifier struct {
	issuer            string
	maxAgeIAT         time.Duration
	offset            time.Duration
	supportedSignAlgs []string
	keySet            oidc.KeySet
}

// Issuer implements oidc.Verifier interface
func (i *accessTokenVerifier) Issuer() string {
	return i.issuer
}

// MaxAgeIAT implements oidc.Verifier interface
func (i *accessTokenVerifier) MaxAgeIAT() time.Duration {
	return i.maxAgeIAT
}

// Offset implements oidc.Verifier interface
func (i *accessTokenVerifier) Offset() time.Duration {
	return i.offset
}

// SupportedSignAlgs implements AccessTokenVerifier interface
func (i *accessTokenVerifier) SupportedSignAlgs() []string {
	return i.supportedSignAlgs
}

// KeySet implements AccessTokenVerifier interface
func (i *accessTokenVerifier) KeySet() oidc.KeySet {
	return i.keySet
}

type AccessTokenVerifierOpt func(*accessTokenVerifier)

func WithSupportedAccessTokenSigningAlgorithms(algs ...string) AccessTokenVerifierOpt {
	return func(verifier *accessTokenVerifier) {
		verifier.supportedSignAlgs = algs
	}
}

func NewAccessTokenVerifier(issuer string, keySet oidc.KeySet, opts ...AccessTokenVerifierOpt) AccessTokenVerifier {
	verifier := &accessTokenVerifier{
		issuer: issuer,
		keySet: keySet,
	}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

// VerifyAccessToken validates the access token (issuer, signature and expiration)
func VerifyAccessToken[C oidc.Claims](ctx context.Context, token string, v AccessTokenVerifier) (claims C, err error) {
	var nilClaims C

	decrypted, err := oidc.DecryptToken(token)
	if err != nil {
		return nilClaims, err
	}
	payload, err := oidc.ParseToken(decrypted, &claims)
	if err != nil {
		return nilClaims, err
	}

	if err := oidc.CheckIssuer(claims, v.Issuer()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs(), v.KeySet()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckExpiration(claims, v.Offset()); err != nil {
		return nilClaims, err
	}

	return claims, nil
}

package op

import (
	"context"
	"time"

	"github.com/zitadel/oidc/pkg/oidc"
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
	maxAge            time.Duration
	acr               oidc.ACRVerifier
	keySet            oidc.KeySet
}

//Issuer implements oidc.Verifier interface
func (i *accessTokenVerifier) Issuer() string {
	return i.issuer
}

//MaxAgeIAT implements oidc.Verifier interface
func (i *accessTokenVerifier) MaxAgeIAT() time.Duration {
	return i.maxAgeIAT
}

//Offset implements oidc.Verifier interface
func (i *accessTokenVerifier) Offset() time.Duration {
	return i.offset
}

//SupportedSignAlgs implements AccessTokenVerifier interface
func (i *accessTokenVerifier) SupportedSignAlgs() []string {
	return i.supportedSignAlgs
}

//KeySet implements AccessTokenVerifier interface
func (i *accessTokenVerifier) KeySet() oidc.KeySet {
	return i.keySet
}

func NewAccessTokenVerifier(issuer string, keySet oidc.KeySet) AccessTokenVerifier {
	verifier := &accessTokenVerifier{
		issuer: issuer,
		keySet: keySet,
	}
	return verifier
}

//VerifyAccessToken validates the access token (issuer, signature and expiration)
func VerifyAccessToken(ctx context.Context, token string, v AccessTokenVerifier) (oidc.AccessTokenClaims, error) {
	claims := oidc.EmptyAccessTokenClaims()

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

	return claims, nil
}

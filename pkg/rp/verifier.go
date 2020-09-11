package rp

import (
	"context"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

//deprecated: Use IDTokenVerifier or oidc.Verifier
type Verifier interface {

	//Verify checks the access_token and id_token and returns the `id token claims`
	Verify(ctx context.Context, accessToken, idTokenString string) (*oidc.IDTokenClaims, error)

	//VerifyIDToken checks the id_token only and returns its `id token claims`
	VerifyIDToken(ctx context.Context, idTokenString string) (*oidc.IDTokenClaims, error)
}

type IDTokenVerifier interface {
	oidc.Verifier
	ClientID() string
	SupportedSignAlgs() []string
	KeySet() oidc.KeySet
	Nonce(context.Context) string
	ACR() oidc.ACRVerifier
	MaxAge() time.Duration
}

type idTokenVerifier struct {
	issuer            string
	maxAgeIAT         time.Duration
	offset            time.Duration
	clientID          string
	supportedSignAlgs []string
	keySet            oidc.KeySet
	acr               oidc.ACRVerifier
	maxAge            time.Duration
	nonce             func(ctx context.Context) string
}

func (i *idTokenVerifier) Issuer() string {
	return i.issuer
}

func (i *idTokenVerifier) MaxAgeIAT() time.Duration {
	return i.maxAgeIAT
}

func (i *idTokenVerifier) Offset() time.Duration {
	return i.offset
}

func (i *idTokenVerifier) ClientID() string {
	return i.clientID
}

func (i *idTokenVerifier) SupportedSignAlgs() []string {
	return i.supportedSignAlgs
}

func (i *idTokenVerifier) KeySet() oidc.KeySet {
	return i.keySet
}

func (i *idTokenVerifier) Nonce(ctx context.Context) string {
	return i.nonce(ctx)
}

func (i *idTokenVerifier) ACR() oidc.ACRVerifier {
	return i.acr
}

func (i *idTokenVerifier) MaxAge() time.Duration {
	return i.maxAge
}

func NewIDTokenVerifier(issuer, clientID string, keySet oidc.KeySet) IDTokenVerifier {
	return &idTokenVerifier{
		issuer:   issuer,
		clientID: clientID,
		keySet:   keySet,
		offset:   5 * time.Second,
	}
}

//VerifyTokens implement the Token Response Validation as defined in OIDC specification
//https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
func VerifyTokens(ctx context.Context, accessToken, idTokenString string, v IDTokenVerifier) (*oidc.IDTokenClaims, error) {
	idToken, err := VerifyIDToken(ctx, idTokenString, v)
	if err != nil {
		return nil, err
	}
	if err := VerifyAccessToken(accessToken, idToken.AccessTokenHash, idToken.Signature); err != nil {
		return nil, err
	}
	return idToken, nil
}

//VerifyIDToken validates the id token according to
//https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func VerifyIDToken(ctx context.Context, token string, v IDTokenVerifier) (*oidc.IDTokenClaims, error) {
	claims := new(oidc.IDTokenClaims)

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

	if err = oidc.CheckAudience(claims, v.ClientID()); err != nil {
		return nil, err
	}

	if err = oidc.CheckAuthorizedParty(claims, v.ClientID()); err != nil {
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

	if err = oidc.CheckNonce(claims, v.Nonce(ctx)); err != nil {
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

//VerifyAccessToken validates the access token according to
//https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
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

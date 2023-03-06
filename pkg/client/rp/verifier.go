package rp

import (
	"context"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type IDTokenVerifier interface {
	oidc.Verifier
	ClientID() string
	SupportedSignAlgs() []string
	KeySet() oidc.KeySet
	Nonce(context.Context) string
	ACR() oidc.ACRVerifier
	MaxAge() time.Duration
}

// VerifyTokens implement the Token Response Validation as defined in OIDC specification
// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
func VerifyTokens[C oidc.IDClaims](ctx context.Context, accessToken, idToken string, v IDTokenVerifier) (claims C, err error) {
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
func VerifyIDToken[C oidc.Claims](ctx context.Context, token string, v IDTokenVerifier) (claims C, err error) {
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

	if err = oidc.CheckIssuer(claims, v.Issuer()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAudience(claims, v.ClientID()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAuthorizedParty(claims, v.ClientID()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs(), v.KeySet()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckExpiration(claims, v.Offset()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckIssuedAt(claims, v.MaxAgeIAT(), v.Offset()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckNonce(claims, v.Nonce(ctx)); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAuthorizationContextClassReference(claims, v.ACR()); err != nil {
		return nilClaims, err
	}

	if err = oidc.CheckAuthTime(claims, v.MaxAge()); err != nil {
		return nilClaims, err
	}
	return claims, nil
}

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

// NewIDTokenVerifier returns an implementation of `IDTokenVerifier`
// for `VerifyTokens` and `VerifyIDToken`
func NewIDTokenVerifier(issuer, clientID string, keySet oidc.KeySet, options ...VerifierOption) IDTokenVerifier {
	v := &idTokenVerifier{
		issuer:   issuer,
		clientID: clientID,
		keySet:   keySet,
		offset:   time.Second,
		nonce: func(_ context.Context) string {
			return ""
		},
	}

	for _, opts := range options {
		opts(v)
	}

	return v
}

// VerifierOption is the type for providing dynamic options to the IDTokenVerifier
type VerifierOption func(*idTokenVerifier)

// WithIssuedAtOffset mitigates the risk of iat to be in the future
// because of clock skews with the ability to add an offset to the current time
func WithIssuedAtOffset(offset time.Duration) func(*idTokenVerifier) {
	return func(v *idTokenVerifier) {
		v.offset = offset
	}
}

// WithIssuedAtMaxAge provides the ability to define the maximum duration between iat and now
func WithIssuedAtMaxAge(maxAge time.Duration) func(*idTokenVerifier) {
	return func(v *idTokenVerifier) {
		v.maxAgeIAT = maxAge
	}
}

// WithNonce sets the function to check the nonce
func WithNonce(nonce func(context.Context) string) VerifierOption {
	return func(v *idTokenVerifier) {
		v.nonce = nonce
	}
}

// WithACRVerifier sets the verifier for the acr claim
func WithACRVerifier(verifier oidc.ACRVerifier) VerifierOption {
	return func(v *idTokenVerifier) {
		v.acr = verifier
	}
}

// WithAuthTimeMaxAge provides the ability to define the maximum duration between auth_time and now
func WithAuthTimeMaxAge(maxAge time.Duration) VerifierOption {
	return func(v *idTokenVerifier) {
		v.maxAge = maxAge
	}
}

// WithSupportedSigningAlgorithms overwrites the default RS256 signing algorithm
func WithSupportedSigningAlgorithms(algs ...string) VerifierOption {
	return func(v *idTokenVerifier) {
		v.supportedSignAlgs = algs
	}
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

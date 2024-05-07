package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	str "github.com/zitadel/oidc/v3/pkg/strings"
)

type Claims interface {
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
	GetExpiration() time.Time
	GetIssuedAt() time.Time
	GetNonce() string
	GetAuthenticationContextClassReference() string
	GetAuthTime() time.Time
	GetAuthorizedParty() string
	ClaimsSignature
}

type ClaimsSignature interface {
	SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm)
}

type IDClaims interface {
	Claims
	GetSignatureAlgorithm() jose.SignatureAlgorithm
	GetAccessTokenHash() string
}

var (
	ErrParse                   = errors.New("parsing of request failed")
	ErrIssuerInvalid           = errors.New("issuer does not match")
	ErrSubjectMissing          = errors.New("subject missing")
	ErrAudience                = errors.New("audience is not valid")
	ErrAzpMissing              = errors.New("authorized party is not set. If Token is valid for multiple audiences, azp must not be empty")
	ErrAzpInvalid              = errors.New("authorized party is not valid")
	ErrSignatureMissing        = errors.New("id_token does not contain a signature")
	ErrSignatureMultiple       = errors.New("id_token contains multiple signatures")
	ErrSignatureUnsupportedAlg = errors.New("signature algorithm not supported")
	ErrSignatureInvalidPayload = errors.New("signature does not match Payload")
	ErrSignatureInvalid        = errors.New("invalid signature")
	ErrExpired                 = errors.New("token has expired")
	ErrIatMissing              = errors.New("issuedAt of token is missing")
	ErrIatInFuture             = errors.New("issuedAt of token is in the future")
	ErrIatToOld                = errors.New("issuedAt of token is to old")
	ErrNonceInvalid            = errors.New("nonce does not match")
	ErrAcrInvalid              = errors.New("acr is invalid")
	ErrAuthTimeNotPresent      = errors.New("claim `auth_time` of token is missing")
	ErrAuthTimeToOld           = errors.New("auth time of token is too old")
	ErrAtHash                  = errors.New("at_hash does not correspond to access token")
)

// Verifier caries configuration for the various token verification
// functions. Use package specific constructor functions to know
// which values need to be set.
type Verifier struct {
	Issuer            string
	MaxAgeIAT         time.Duration
	Offset            time.Duration
	ClientID          string
	SupportedSignAlgs []string
	MaxAge            time.Duration
	ACR               ACRVerifier
	KeySet            KeySet
	Nonce             func(ctx context.Context) string
}

// ACRVerifier specifies the function to be used by the `DefaultVerifier` for validating the acr claim
type ACRVerifier func(string) error

// DefaultACRVerifier implements `ACRVerifier` returning an error
// if none of the provided values matches the acr claim
func DefaultACRVerifier(possibleValues []string) ACRVerifier {
	return func(acr string) error {
		if !str.Contains(possibleValues, acr) {
			return fmt.Errorf("expected one of: %v, got: %q", possibleValues, acr)
		}
		return nil
	}
}

func DecryptToken(tokenString string) (string, error) {
	return tokenString, nil // TODO: impl
}

func ParseToken(tokenString string, claims any) ([]byte, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: token contains an invalid number of segments", ErrParse)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed jwt payload: %v", ErrParse, err)
	}
	err = json.Unmarshal(payload, claims)
	return payload, err
}

func CheckSubject(claims Claims) error {
	if claims.GetSubject() == "" {
		return ErrSubjectMissing
	}
	return nil
}

func CheckIssuer(claims Claims, issuer string) error {
	if claims.GetIssuer() != issuer {
		return fmt.Errorf("%w: Expected: %s, got: %s", ErrIssuerInvalid, issuer, claims.GetIssuer())
	}
	return nil
}

func CheckAudience(claims Claims, clientID string) error {
	if !str.Contains(claims.GetAudience(), clientID) {
		return fmt.Errorf("%w: Audience must contain client_id %q", ErrAudience, clientID)
	}

	// TODO: check aud trusted
	return nil
}

// CheckAuthorizedParty checks azp (authorized party) claim requirements.
//
// If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
// If an azp Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func CheckAuthorizedParty(claims Claims, clientID string) error {
	if len(claims.GetAudience()) > 1 {
		if claims.GetAuthorizedParty() == "" {
			return ErrAzpMissing
		}
	}
	if claims.GetAuthorizedParty() != "" && claims.GetAuthorizedParty() != clientID {
		return fmt.Errorf("%w: azp %q must be equal to client_id %q", ErrAzpInvalid, claims.GetAuthorizedParty(), clientID)
	}
	return nil
}

func CheckSignature(ctx context.Context, token string, payload []byte, claims ClaimsSignature, supportedSigAlgs []string, set KeySet) error {
	jws, err := jose.ParseSigned(token, toJoseSignatureAlgorithms(supportedSigAlgs))
	if err != nil {
		if strings.HasPrefix(err.Error(), "go-jose/go-jose: unexpected signature algorithm") {
			// TODO(v4): we should wrap errors instead of returning static ones.
			// This is a workaround so we keep returning the same error for now.
			return ErrSignatureUnsupportedAlg
		}
		return ErrParse
	}
	if len(jws.Signatures) == 0 {
		return ErrSignatureMissing
	}
	if len(jws.Signatures) > 1 {
		return ErrSignatureMultiple
	}
	sig := jws.Signatures[0]

	signedPayload, err := set.VerifySignature(ctx, jws)
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrSignatureInvalid, err)
	}

	if !bytes.Equal(signedPayload, payload) {
		return ErrSignatureInvalidPayload
	}

	claims.SetSignatureAlgorithm(jose.SignatureAlgorithm(sig.Header.Algorithm))

	return nil
}

// TODO(v4): Use the new jose.SignatureAlgorithm type directly, instead of string.
func toJoseSignatureAlgorithms(algorithms []string) []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, len(algorithms))
	for i := range algorithms {
		out[i] = jose.SignatureAlgorithm(algorithms[i])
	}
	if len(out) == 0 {
		out = append(out, jose.RS256, jose.ES256, jose.PS256)
	}
	return out
}

func CheckExpiration(claims Claims, offset time.Duration) error {
	expiration := claims.GetExpiration()
	if !time.Now().Add(offset).Before(expiration) {
		return ErrExpired
	}
	return nil
}

func CheckIssuedAt(claims Claims, maxAgeIAT, offset time.Duration) error {
	issuedAt := claims.GetIssuedAt()
	if issuedAt.IsZero() {
		return ErrIatMissing
	}
	nowWithOffset := time.Now().Add(offset).Round(time.Second)
	if issuedAt.After(nowWithOffset) {
		return fmt.Errorf("%w: (iat: %v, now with offset: %v)", ErrIatInFuture, issuedAt, nowWithOffset)
	}
	if maxAgeIAT == 0 {
		return nil
	}
	maxAge := time.Now().Add(-maxAgeIAT).Round(time.Second)
	if issuedAt.Before(maxAge) {
		return fmt.Errorf("%w: must not be older than %v, but was %v (%v to old)", ErrIatToOld, maxAge, issuedAt, maxAge.Sub(issuedAt))
	}
	return nil
}

func CheckNonce(claims Claims, nonce string) error {
	if claims.GetNonce() != nonce {
		return fmt.Errorf("%w: expected %q but was %q", ErrNonceInvalid, nonce, claims.GetNonce())
	}
	return nil
}

func CheckAuthorizationContextClassReference(claims Claims, acr ACRVerifier) error {
	if acr != nil {
		if err := acr(claims.GetAuthenticationContextClassReference()); err != nil {
			return fmt.Errorf("%w: %v", ErrAcrInvalid, err)
		}
	}
	return nil
}

func CheckAuthTime(claims Claims, maxAge time.Duration) error {
	if maxAge == 0 {
		return nil
	}
	if claims.GetAuthTime().IsZero() {
		return ErrAuthTimeNotPresent
	}
	authTime := claims.GetAuthTime()
	maxAuthTime := time.Now().Add(-maxAge).Round(time.Second)
	if authTime.Before(maxAuthTime) {
		return fmt.Errorf("%w: must not be older than %v, but was %v (%v to old)", ErrAuthTimeToOld, maxAge, authTime, maxAuthTime.Sub(authTime))
	}
	return nil
}

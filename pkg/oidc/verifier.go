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

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/utils"
)

type Claims interface {
	GetIssuer() string
	GetAudience() []string
	GetExpiration() time.Time
	GetIssuedAt() time.Time
	GetNonce() string
	GetAuthenticationContextClassReference() string
	GetAuthTime() time.Time
	GetAuthorizedParty() string
	SetSignature(algorithm jose.SignatureAlgorithm)
}

var (
	ErrParse         = errors.New("")
	ErrIssuerInvalid = errors.New("issuer does not match")

	ErrAudience = errors.New("audience is not valid")

	ErrAzpMissing = errors.New("authorized party is not set. If Token is valid for multiple audiences, azp must not be empty")
	ErrAzpInvalid = errors.New("authorized party is not valid")

	ErrSignatureMissing        = errors.New("id_token does not contain a signature")
	ErrSignatureMultiple       = errors.New("id_token contains multiple signatures")
	ErrSignatureUnsupportedAlg = errors.New("signature algorithm not supported")
	ErrSignatureInvalidPayload = errors.New("signature does not match Payload")

	ErrExpired = errors.New("token has expired")

	ErrIatInFuture = errors.New("issuedAt of token is in the future")

	ErrIatToOld = errors.New("issuedAt of token is to old")
	//
	//ErrNonceInvalid = func(expected, actual string) *validationError {
	//	return ValidationError("nonce does not match. Expected: %s, got: %s", expected, actual)
	//}
	ErrAcrInvalid         = errors.New("acr is invalid")
	ErrAuthTimeNotPresent = errors.New("claim `auth_time` of token is missing")
	ErrAuthTimeToOld      = errors.New("auth time of token is to old")

	ErrAtHash = errors.New("at_hash does not correspond to access token")
)

//ACRVerifier specifies the function to be used by the `DefaultVerifier` for validating the acr claim
type ACRVerifier func(string) error

func DecryptToken(tokenString string) (string, error) {
	return tokenString, nil //TODO: impl
}

func ParseToken(tokenString string, claims interface{}) ([]byte, error) {
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

type Verifier interface {
	Issuer() string
	ClientID() string
	SupportedSignAlgs() []string
	KeySet() KeySet
	ACR() ACRVerifier
	MaxAge() time.Duration
	MaxAgeIAT() time.Duration
	Offset() time.Duration
}

func CheckIssuer(issuer string, i Verifier) error {
	if i.Issuer() != issuer {
		return fmt.Errorf("%w: Expected: %s, got: %s", ErrIssuerInvalid, i.Issuer(), issuer)
	}
	return nil
}

func CheckAudience(audiences []string, i Verifier) error {
	if !utils.Contains(audiences, i.ClientID()) {
		return fmt.Errorf("%w: Audience must contain client_id (%s)", ErrAudience, i.ClientID())
	}

	//TODO: check aud trusted
	return nil
}

//4. if multiple aud strings --> check if azp
//5. if azp --> check azp == client_id
func CheckAuthorizedParty(audiences []string, authorizedParty string, v Verifier) error {
	if len(audiences) > 1 {
		if authorizedParty == "" {
			return ErrAzpMissing
		}
	}
	if authorizedParty != "" && authorizedParty != v.ClientID() {
		return fmt.Errorf("%w: azp %q must be equal to client_id %q", ErrAzpInvalid, authorizedParty, v.ClientID())
	}
	return nil
}

func CheckSignature(ctx context.Context, idTokenString string, payload []byte, claims Claims, v Verifier) error {
	jws, err := jose.ParseSigned(idTokenString)
	if err != nil {
		return err
	}
	if len(jws.Signatures) == 0 {
		return ErrSignatureMissing
	}
	if len(jws.Signatures) > 1 {
		return ErrSignatureMultiple
	}
	sig := jws.Signatures[0]
	supportedSigAlgs := v.SupportedSignAlgs()
	if len(supportedSigAlgs) == 0 {
		supportedSigAlgs = []string{"RS256"}
	}
	if !utils.Contains(supportedSigAlgs, sig.Header.Algorithm) {
		return fmt.Errorf("%w: id token signed with unsupported algorithm, expected %q got %q", ErrSignatureUnsupportedAlg, supportedSigAlgs, sig.Header.Algorithm)
	}

	signedPayload, err := v.KeySet().VerifySignature(ctx, jws)
	if err != nil {
		return err
	}

	if !bytes.Equal(signedPayload, payload) {
		return ErrSignatureInvalidPayload
	}

	claims.SetSignature(jose.SignatureAlgorithm(sig.Header.Algorithm))

	return nil
}

func CheckExpiration(expiration time.Time, v Verifier) error {
	expiration = expiration.Round(time.Second)
	if !time.Now().UTC().Add(v.Offset()).Before(expiration) {
		return ErrExpired
	}
	return nil
}

func CheckIssuedAt(issuedAt time.Time, v Verifier) error {
	issuedAt = issuedAt.Round(time.Second)
	offset := time.Now().UTC().Add(v.Offset()).Round(time.Second)
	if issuedAt.After(offset) {
		return fmt.Errorf("%w: (iat: %v, now with offset: %v)", ErrIatInFuture, issuedAt, offset)
	}
	if v.MaxAgeIAT() == 0 {
		return nil
	}
	maxAge := time.Now().UTC().Add(-v.MaxAgeIAT()).Round(time.Second)
	if issuedAt.Before(maxAge) {
		return fmt.Errorf("%w: must not be older than %v, but was %v (%v to old)", ErrIatToOld, maxAge, issuedAt, maxAge.Sub(issuedAt))
	}
	return nil
}

/*
func (v *DefaultVerifier) CheckNonce(nonce string) error {
	if v.config.nonce == "" {
		return nil
	}
	if v.config.nonce != nonce {
		return ErrNonceInvalid(v.config.nonce, nonce)
	}
	return nil
}*/
func CheckAuthorizationContextClassReference(acr string, v Verifier) error {
	if v.ACR() != nil {
		if err := v.ACR()(acr); err != nil {
			return fmt.Errorf("%w: %v", ErrAcrInvalid, err)
		}
	}
	return nil
}
func CheckAuthTime(authTime time.Time, v Verifier) error {
	if v.MaxAge() == 0 {
		return nil
	}
	if authTime.IsZero() {
		return ErrAuthTimeNotPresent
	}
	authTime = authTime.Round(time.Second)
	maxAge := time.Now().UTC().Add(-v.MaxAge()).Round(time.Second)
	if authTime.Before(maxAge) {
		return fmt.Errorf("%w: must not be older than %v, but was %v (%v to old)", ErrAuthTimeToOld, maxAge, authTime, maxAge.Sub(authTime))
	}
	return nil
}

package op

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/pkg/oidc"
)

type JWTProfileVerifier interface {
	oidc.Verifier
	Storage() jwtProfileKeyStorage
	CheckSubject(request *oidc.JWTTokenRequest) error
}

type jwtProfileVerifier struct {
	storage      jwtProfileKeyStorage
	subjectCheck func(request *oidc.JWTTokenRequest) error
	issuer       string
	maxAgeIAT    time.Duration
	offset       time.Duration
}

//NewJWTProfileVerifier creates a oidc.Verifier for JWT Profile assertions (authorization grant and client authentication)
func NewJWTProfileVerifier(storage jwtProfileKeyStorage, issuer string, maxAgeIAT, offset time.Duration, opts ...JWTProfileVerifierOption) JWTProfileVerifier {
	j := &jwtProfileVerifier{
		storage:      storage,
		subjectCheck: SubjectIsIssuer,
		issuer:       issuer,
		maxAgeIAT:    maxAgeIAT,
		offset:       offset,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j
}

type JWTProfileVerifierOption func(*jwtProfileVerifier)

func SubjectCheck(check func(request *oidc.JWTTokenRequest) error) JWTProfileVerifierOption {
	return func(verifier *jwtProfileVerifier) {
		verifier.subjectCheck = check
	}
}

func (v *jwtProfileVerifier) Issuer() string {
	return v.issuer
}

func (v *jwtProfileVerifier) Storage() jwtProfileKeyStorage {
	return v.storage
}

func (v *jwtProfileVerifier) MaxAgeIAT() time.Duration {
	return v.maxAgeIAT
}

func (v *jwtProfileVerifier) Offset() time.Duration {
	return v.offset
}

func (v *jwtProfileVerifier) CheckSubject(request *oidc.JWTTokenRequest) error {
	return v.subjectCheck(request)
}

//VerifyJWTAssertion verifies the assertion string from JWT Profile (authorization grant and client authentication)
//
//checks audience, exp, iat, signature and that issuer and sub are the same
func VerifyJWTAssertion(ctx context.Context, assertion string, v JWTProfileVerifier) (*oidc.JWTTokenRequest, error) {
	request := new(oidc.JWTTokenRequest)
	payload, err := oidc.ParseToken(assertion, request)
	if err != nil {
		return nil, err
	}

	if err = oidc.CheckAudience(request, v.Issuer()); err != nil {
		return nil, err
	}

	if err = oidc.CheckExpiration(request, v.Offset()); err != nil {
		return nil, err
	}

	if err = oidc.CheckIssuedAt(request, v.MaxAgeIAT(), v.Offset()); err != nil {
		return nil, err
	}

	if err = v.CheckSubject(request); err != nil {
		return nil, err
	}

	keySet := &jwtProfileKeySet{v.Storage(), request.Issuer}

	if err = oidc.CheckSignature(ctx, assertion, payload, request, nil, keySet); err != nil {
		return nil, err
	}
	return request, nil
}

type jwtProfileKeyStorage interface {
	GetKeyByIDAndUserID(ctx context.Context, keyID, userID string) (*jose.JSONWebKey, error)
}

func SubjectIsIssuer(request *oidc.JWTTokenRequest) error {
	if request.Issuer != request.Subject {
		return errors.New("delegation not allowed, issuer and sub must be identical")
	}
	return nil
}

type jwtProfileKeySet struct {
	storage jwtProfileKeyStorage
	userID  string
}

//VerifySignature implements oidc.KeySet by getting the public key from Storage implementation
func (k *jwtProfileKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error) {
	keyID, _ := oidc.GetKeyIDAndAlg(jws)
	key, err := k.storage.GetKeyByIDAndUserID(ctx, keyID, k.userID)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}
	return jws.Verify(key)
}

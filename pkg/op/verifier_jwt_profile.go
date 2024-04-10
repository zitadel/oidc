package op

import (
	"context"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// JWTProfileVerfiier extends oidc.Verifier with
// a jwtProfileKeyStorage and a function to check
// the subject in a token.
type JWTProfileVerifier struct {
	oidc.Verifier
	Storage      JWTProfileKeyStorage
	keySet       oidc.KeySet
	CheckSubject func(request *oidc.JWTTokenRequest) error
}

// NewJWTProfileVerifier creates a oidc.Verifier for JWT Profile assertions (authorization grant and client authentication)
func NewJWTProfileVerifier(storage JWTProfileKeyStorage, issuer string, maxAgeIAT, offset time.Duration, opts ...JWTProfileVerifierOption) *JWTProfileVerifier {
	return newJWTProfileVerifier(storage, nil, issuer, maxAgeIAT, offset, opts...)
}

// NewJWTProfileVerifierKeySet creates a oidc.Verifier for JWT Profile assertions (authorization grant and client authentication)
func NewJWTProfileVerifierKeySet(keySet oidc.KeySet, issuer string, maxAgeIAT, offset time.Duration, opts ...JWTProfileVerifierOption) *JWTProfileVerifier {
	return newJWTProfileVerifier(nil, keySet, issuer, maxAgeIAT, offset, opts...)
}

func newJWTProfileVerifier(storage JWTProfileKeyStorage, keySet oidc.KeySet, issuer string, maxAgeIAT, offset time.Duration, opts ...JWTProfileVerifierOption) *JWTProfileVerifier {
	j := &JWTProfileVerifier{
		Verifier: oidc.Verifier{
			Issuer:    issuer,
			MaxAgeIAT: maxAgeIAT,
			Offset:    offset,
		},
		Storage:      storage,
		keySet:       keySet,
		CheckSubject: SubjectIsIssuer,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j
}

type JWTProfileVerifierOption func(*JWTProfileVerifier)

// SubjectCheck sets a custom function to check the subject.
// Defaults to SubjectIsIssuer()
func SubjectCheck(check func(request *oidc.JWTTokenRequest) error) JWTProfileVerifierOption {
	return func(verifier *JWTProfileVerifier) {
		verifier.CheckSubject = check
	}
}

// VerifyJWTAssertion verifies the assertion string from JWT Profile (authorization grant and client authentication)
//
// checks audience, exp, iat, signature and that issuer and sub are the same
func VerifyJWTAssertion(ctx context.Context, assertion string, v *JWTProfileVerifier) (*oidc.JWTTokenRequest, error) {
	ctx, span := tracer.Start(ctx, "VerifyJWTAssertion")
	defer span.End()

	request := new(oidc.JWTTokenRequest)
	payload, err := oidc.ParseToken(assertion, request)
	if err != nil {
		return nil, err
	}

	if err = oidc.CheckAudience(request, v.Issuer); err != nil {
		return nil, err
	}

	if err = oidc.CheckExpiration(request, v.Offset); err != nil {
		return nil, err
	}

	if err = oidc.CheckIssuedAt(request, v.MaxAgeIAT, v.Offset); err != nil {
		return nil, err
	}

	if err = v.CheckSubject(request); err != nil {
		return nil, err
	}

	keySet := v.keySet
	if keySet == nil {
		keySet = &jwtProfileKeySet{storage: v.Storage, clientID: request.Issuer}
	}
	if err = oidc.CheckSignature(ctx, assertion, payload, request, nil, keySet); err != nil {
		return nil, err
	}
	return request, nil
}

type JWTProfileKeyStorage interface {
	GetKeyByIDAndClientID(ctx context.Context, keyID, userID string) (*jose.JSONWebKey, error)
}

// SubjectIsIssuer
func SubjectIsIssuer(request *oidc.JWTTokenRequest) error {
	if request.Issuer != request.Subject {
		return errors.New("delegation not allowed, issuer and sub must be identical")
	}
	return nil
}

type jwtProfileKeySet struct {
	storage  JWTProfileKeyStorage
	clientID string
}

// VerifySignature implements oidc.KeySet by getting the public key from Storage implementation
func (k *jwtProfileKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error) {
	ctx, span := tracer.Start(ctx, "VerifySignature")
	defer span.End()

	keyID, _ := oidc.GetKeyIDAndAlg(jws)
	key, err := k.storage.GetKeyByIDAndClientID(ctx, keyID, k.clientID)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}
	return jws.Verify(key)
}

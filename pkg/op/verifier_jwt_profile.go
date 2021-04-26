package op

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type JWTProfileVerifier interface {
	oidc.Verifier
	Storage() Storage
}

type jwtProfileVerifier struct {
	storage   Storage
	issuer    string
	maxAgeIAT time.Duration
	offset    time.Duration
}

func NewJWTProfileVerifier(storage Storage, issuer string, maxAgeIAT, offset time.Duration) JWTProfileVerifier {
	return &jwtProfileVerifier{
		storage:   storage,
		issuer:    issuer,
		maxAgeIAT: maxAgeIAT,
		offset:    offset,
	}
}

func (v *jwtProfileVerifier) Issuer() string {
	return v.issuer
}

func (v *jwtProfileVerifier) Storage() Storage {
	return v.storage
}

func (v *jwtProfileVerifier) MaxAgeIAT() time.Duration {
	return v.maxAgeIAT
}

func (v *jwtProfileVerifier) Offset() time.Duration {
	return v.offset
}

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

	if request.Issuer != request.Subject {
		//TODO: implement delegation (openid core / oauth rfc)
		return nil, errors.New("delegation not yet implemented, issuer and sub must be identical")
	}

	keySet := &jwtProfileKeySet{v.Storage(), request.Issuer}

	if err = oidc.CheckSignature(ctx, assertion, payload, request, nil, keySet); err != nil {
		return nil, err
	}
	return request, nil
}

type jwtProfileKeySet struct {
	Storage
	userID string
}

func (k *jwtProfileKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error) {
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	key, err := k.Storage.GetKeyByIDAndUserID(ctx, keyID, k.userID)
	if err != nil {
		return nil, fmt.Errorf("error fetching keys: %w", err)
	}
	if key.Algorithm != alg {

	}
	return jws.Verify(&key)
}

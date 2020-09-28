package op

import (
	"context"
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/oidc/grants/tokenexchange"
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

func VerifyJWTAssertion(ctx context.Context, profileRequest *tokenexchange.JWTProfileRequest, v JWTProfileVerifier) (*oidc.JWTTokenRequest, error) {
	request := new(oidc.JWTTokenRequest)
	payload, err := oidc.ParseToken(profileRequest.Assertion, request)
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
	}

	keySet := &jwtProfileKeySet{v.Storage(), request.Subject}

	if err = oidc.CheckSignature(ctx, profileRequest.Assertion, payload, request, nil, keySet); err != nil {
		return nil, err
	}
	request.Scopes = profileRequest.Scope
	return request, nil
}

type jwtProfileKeySet struct {
	Storage
	userID string
}

func (k *jwtProfileKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error) {
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}
	key, err := k.Storage.GetKeyByIDAndUserID(ctx, keyID, k.userID)
	if err != nil {
		return nil, errors.New("error fetching keys")
	}
	payload, err, ok := oidc.CheckKey(keyID, jws, *key)
	if !ok {
		return nil, errors.New("invalid kid")
	}
	return payload, err
}

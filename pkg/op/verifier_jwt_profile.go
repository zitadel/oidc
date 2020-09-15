package op

import (
	"context"
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type JWTProfileVerifier interface {
	oidc.Verifier
	Storage() Storage
}

type jwtProfileVerifier struct {
	storage Storage
	issuer  string
}

func NewJWTProfileVerifier(storage Storage, issuer string) JWTProfileVerifier {
	return &jwtProfileVerifier{
		storage: storage,
		issuer:  issuer,
	}
}

func (v *jwtProfileVerifier) Issuer() string {
	return v.issuer
}

func (v *jwtProfileVerifier) Storage() Storage {
	return v.storage
}

func (v *jwtProfileVerifier) MaxAgeIAT() time.Duration {
	//TODO: define in conf/opts
	return 1 * time.Hour
}

func (v *jwtProfileVerifier) Offset() time.Duration {
	//TODO: define in conf/opts
	return time.Second
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
	}

	keySet := &jwtProfileKeySet{v.Storage(), request.Subject}

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

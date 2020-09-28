package oidc

import (
	"context"

	"gopkg.in/square/go-jose.v2"
)

//KeySet represents a set of JSON Web Keys
// - remotely fetch via discovery and jwks_uri -> `remoteKeySet`
// - held by the OP itself in storage -> `openIDKeySet`
// - dynamically aggregated by request for OAuth JWT Profile Assertion -> `jwtProfileKeySet`
type KeySet interface {
	//VerifySignature verifies the signature with the given keyset and returns the raw payload
	VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error)
}

//CheckKey searches the given JSON Web Keys for the requested key ID
//and verifies the JSON Web Signature with the found key
//
//will return false but no error if key ID is not found
func CheckKey(keyID string, jws *jose.JSONWebSignature, keys ...jose.JSONWebKey) ([]byte, error, bool) {
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			payload, err := jws.Verify(&key)
			return payload, err, true
		}
	}
	return nil, nil, false
}

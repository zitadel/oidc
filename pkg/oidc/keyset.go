package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"gopkg.in/square/go-jose.v2"
)

const (
	KeyUseSignature = "sig"
)

//KeySet represents a set of JSON Web Keys
// - remotely fetch via discovery and jwks_uri -> `remoteKeySet`
// - held by the OP itself in storage -> `openIDKeySet`
// - dynamically aggregated by request for OAuth JWT Profile Assertion -> `jwtProfileKeySet`
type KeySet interface {
	//VerifySignature verifies the signature with the given keyset and returns the raw payload
	VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error)
}

//GetKeyIDAndAlg returns the `kid` and `alg` claim from the JWS header
func GetKeyIDAndAlg(jws *jose.JSONWebSignature) (string, string) {
	keyID := ""
	alg := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		alg = sig.Header.Algorithm
		break
	}
	return keyID, alg
}

//FindKey searches the given JSON Web Keys for the requested key ID, usage and key type
//
//will return the key immediately if matches exact (id, usage, type)
//
//will return false none or multiple match
func FindKey(keyID, use, expectedAlg string, keys ...jose.JSONWebKey) (jose.JSONWebKey, bool) {
	var validKeys []jose.JSONWebKey
	for _, key := range keys {
		if key.KeyID == keyID && key.Use == use && algToKeyType(key.Key, expectedAlg) {
			if keyID != "" {
				return key, true
			}
			validKeys = append(validKeys, key)
		}
	}
	if len(validKeys) == 1 {
		return validKeys[0], true
	}
	return jose.JSONWebKey{}, false
}

func algToKeyType(key interface{}, alg string) bool {
	switch alg[0] {
	case 'R', 'P':
		_, ok := key.(*rsa.PublicKey)
		return ok
	case 'E':
		_, ok := key.(*ecdsa.PublicKey)
		return ok
	case 'O':
		_, ok := key.(*ed25519.PublicKey)
		return ok
	default:
		return false
	}
}

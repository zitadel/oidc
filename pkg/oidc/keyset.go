package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	KeyUseSignature = "sig"
)

var (
	ErrKeyMultiple = errors.New("multiple possible keys match")
	ErrKeyNone     = errors.New("no possible keys matches")
)

// KeySet represents a set of JSON Web Keys
// - remotely fetch via discovery and jwks_uri -> `remoteKeySet`
// - held by the OP itself in storage -> `openIDKeySet`
// - dynamically aggregated by request for OAuth JWT Profile Assertion -> `jwtProfileKeySet`
type KeySet interface {
	// VerifySignature verifies the signature with the given keyset and returns the raw payload
	VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error)
}

// GetKeyIDAndAlg returns the `kid` and `alg` claim from the JWS header
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

// FindKey searches the given JSON Web Keys for the requested key ID, usage and key type
//
// will return the key immediately if matches exact (id, usage, type)
//
// will return false none or multiple match
//
// deprecated: use FindMatchingKey which will return an error (more specific) instead of just a bool
// moved implementation already to FindMatchingKey
func FindKey(keyID, use, expectedAlg string, keys ...jose.JSONWebKey) (jose.JSONWebKey, bool) {
	key, err := FindMatchingKey(keyID, use, expectedAlg, keys...)
	return key, err == nil
}

// FindMatchingKey searches the given JSON Web Keys for the requested key ID, usage and alg type
//
// will return the key immediately if matches exact (id, usage, type)
//
// will return a specific error if none (ErrKeyNone) or multiple (ErrKeyMultiple) match
func FindMatchingKey(keyID, use, expectedAlg string, keys ...jose.JSONWebKey) (key jose.JSONWebKey, err error) {
	var validKeys []jose.JSONWebKey
	for _, k := range keys {
		// ignore all keys with wrong use (let empty use of published key pass)
		if k.Use != use && k.Use != "" {
			continue
		}
		// ignore all keys with wrong algorithm type
		if !algToKeyType(k.Key, expectedAlg) {
			continue
		}
		// if we get here, use and alg match, so an equal (not empty) keyID is an exact match
		if k.KeyID == keyID && keyID != "" {
			return k, nil
		}
		// keyIDs did not match or at least one was empty (if later, then it could be a match)
		if k.KeyID == "" || keyID == "" {
			validKeys = append(validKeys, k)
		}
	}
	// if we get here, no match was possible at all (use / alg) or no exact match due to
	// the signed JWT and / or the published keys didn't have a kid
	// if later applies and only one key could be found, we'll return it
	// otherwise a corresponding error will be thrown
	if len(validKeys) == 1 {
		return validKeys[0], nil
	}
	if len(validKeys) > 1 {
		return key, ErrKeyMultiple
	}
	return key, ErrKeyNone
}

func algToKeyType(key any, alg string) bool {
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

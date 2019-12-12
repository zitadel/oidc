package utils

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"gopkg.in/square/go-jose.v2"
)

func GetHashAlgorithm(sigAlgorithm jose.SignatureAlgorithm) (hash.Hash, error) {
	switch sigAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256:
		return sha256.New(), nil
	case jose.RS384, jose.ES384, jose.PS384:
		return sha512.New384(), nil
	case jose.RS512, jose.ES512, jose.PS512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("oidc: unsupported signing algorithm %q", sigAlgorithm)
	}
}

func HashString(hash hash.Hash, s string) string {
	hash.Write([]byte(s)) // hash documents that Write will never return an error
	sum := hash.Sum(nil)[:hash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(sum)
}

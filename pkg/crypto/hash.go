package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	jose "github.com/go-jose/go-jose/v4"
)

var ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")

func GetHashAlgorithm(sigAlgorithm jose.SignatureAlgorithm) (hash.Hash, error) {
	switch sigAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256:
		return sha256.New(), nil
	case jose.RS384, jose.ES384, jose.PS384:
		return sha512.New384(), nil
	case jose.RS512, jose.ES512, jose.PS512:
		return sha512.New(), nil

	// There is no published spec for this yet.
	// There is consensus here: https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens
	// Currently go-jose only supports the ed25519 curve key for EdDSA, so we can safely assume sha512 here.
	//
	// TODO: When go-jose ever decides to support ed448, we need to know the "crv" parameter and use shake256 for ed448.
	// The "crv" value is currently not exposed by go-jose.JSONWebKey and is currently only hard-coded to be set during marshalling.
	case jose.EdDSA:
		return sha512.New(), nil

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, sigAlgorithm)
	}
}

func HashString(hash hash.Hash, s string, firstHalf bool) string {
	if hash == nil {
		return s
	}
	//nolint:errcheck
	hash.Write([]byte(s))
	size := hash.Size()
	if firstHalf {
		size = size / 2
	}
	sum := hash.Sum(nil)[:size]
	return base64.RawURLEncoding.EncodeToString(sum)
}

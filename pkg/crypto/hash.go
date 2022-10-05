package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	"gopkg.in/square/go-jose.v2"
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

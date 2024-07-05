package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/go-jose/go-jose/v4"
)

var (
	ErrPEMDecode             = errors.New("PEM decode failed")
	ErrUnsupportedFormat     = errors.New("key is neither in PKCS#1 nor PKCS#8 format")
	ErrUnsupportedPrivateKey = errors.New("unsupported key type, must be RSA, ECDSA or ED25519 private key")
)

func BytesToPrivateKey(b []byte) (crypto.PublicKey, jose.SignatureAlgorithm, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, "", ErrPEMDecode
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, jose.RS256, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", ErrUnsupportedFormat
	}
	switch privateKey := key.(type) {
	case *rsa.PrivateKey:
		return privateKey, jose.RS256, nil
	case ed25519.PrivateKey:
		return privateKey, jose.EdDSA, nil
	case *ecdsa.PrivateKey:
		return privateKey, jose.ES256, nil
	default:
		return nil, "", ErrUnsupportedPrivateKey
	}
}

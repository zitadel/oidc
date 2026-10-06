package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"log/slog"

	"github.com/zitadel/oidc/v3/pkg/op"
)

var _ op.Encrypter = &myCrypto{}
var _ op.Decrypter = &myCrypto{}

// myCrypto demonstrates how to provide your custom implementation of op.Crypto.
// It encrypts with AES-256-GCM, which also authenticates the data.
type myCrypto struct {
	aead   cipher.AEAD
	logger *slog.Logger
}

//lint:ignore U1000 this function is unused but functions as a demonstration on how to use it.
func newMyCrypto(key [32]byte, l *slog.Logger) (*myCrypto, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	// a random nonce is generated for every encryption and prepended to the ciphertext
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &myCrypto{
		aead:   aead,
		logger: l,
	}, nil
}

func (m *myCrypto) Decrypt(s string) (string, error) {
	m.logger.Info("decrypting")
	cipherText, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	plainText, err := m.aead.Open(nil, nil, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func (m *myCrypto) Encrypt(s string) (string, error) {
	m.logger.Info("encrypting")
	cipherText := m.aead.Seal(nil, nil, []byte(s), nil)
	return base64.RawURLEncoding.EncodeToString(cipherText), nil
}

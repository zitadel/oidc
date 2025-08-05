package main

import (
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/op"
	"log/slog"
)

var _ op.Crypto = &myCrypto{}

// myCrypto demonstrates how to provide your custom implementation of op.Crypto.
type myCrypto struct {
	key    string
	logger *slog.Logger
}

func newMyCrypto(key [32]byte, l *slog.Logger) *myCrypto {
	return &myCrypto{
		key:    string(key[:32]),
		logger: l,
	}
}

func (m *myCrypto) Decrypt(s string) (string, error) {
	m.logger.Info("decrypting")
	return crypto.DecryptAES(s, m.key)
}

func (m *myCrypto) Encrypt(s string) (string, error) {
	m.logger.Info("encrypting")
	return crypto.EncryptAES(s, m.key)
}

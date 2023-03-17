package op

import (
	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type Crypto interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type aesCrypto struct {
	key string
}

func NewAESCrypto(key [32]byte) Crypto {
	return &aesCrypto{key: string(key[:32])}
}

func (c *aesCrypto) Encrypt(s string) (string, error) {
	return crypto.EncryptAES(s, c.key)
}

func (c *aesCrypto) Decrypt(s string) (string, error) {
	return crypto.DecryptAES(s, c.key)
}

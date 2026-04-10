package op

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type Encrypter interface {
	Encrypt(string) (string, error)
}
type Decrypter interface {
	Decrypt(string) (string, error)
}

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

type aes256GCMCrypto struct {
	key   []byte
	keyId string
}

func NewAES256GCMCrypto(key [32]byte, keyId string) Crypto {
	return &aes256GCMCrypto{
		key:   key[:],
		keyId: keyId,
	}
}

func (c *aes256GCMCrypto) Encrypt(s string) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.A256GCMKW,
		Key:       c.key,
		KeyID:     c.keyId,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %v", err)
	}

	encrypted, err := encrypter.Encrypt([]byte(s))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %v", err)
	}

	serialized, err := encrypted.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize encrypted value: %v", err)
	}

	return serialized, nil
}

func (c *aes256GCMCrypto) Decrypt(s string) (string, error) {
	jwe, err := jose.ParseEncrypted(s, []jose.KeyAlgorithm{jose.A256GCMKW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return "", fmt.Errorf("failed to create jwe: %v", err)
	}
	decrypted, err := jwe.Decrypt(c.key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt value: %v", err)
	}
	return string(decrypted), nil
}

type CompositeCrypto struct {
	encrypter Encrypter
	// decrypters is a list so that older encrypted values can stil be decrypted.
	decrypters []Decrypter
}

func NewCompositeCrypto(encrypter Encrypter, decrypters []Decrypter) Crypto {
	return &CompositeCrypto{
		encrypter:  encrypter,
		decrypters: decrypters,
	}
}

func (cc CompositeCrypto) Encrypt(s string) (string, error) {
	return cc.encrypter.Encrypt(s)
}

func (cc CompositeCrypto) Decrypt(s string) (string, error) {
	for _, d := range cc.decrypters {
		decrypted, err := d.Decrypt(s)
		if err != nil {
			continue
		}
		return decrypted, nil
	}
	return "", errors.New("failed to decrypt value")
}

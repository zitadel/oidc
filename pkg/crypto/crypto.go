package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var ErrCipherTextBlockSize = errors.New("ciphertext block size is too short")

// EncryptAES encrypts data with [EncryptBytesAES] and returns the result base64url encoded, without padding.
//
// Deprecated: AES-CFB is deprecated since Go 1.24. Use [github.com/zitadel/oidc/v3/pkg/op.NewAES256GCMCrypto]
// for new data, which encrypts with AES-256-GCM. Its output is in a different format, so keep
// [DecryptAES] only to read data that was encrypted with this function.
func EncryptAES(data string, key string) (string, error) {
	encrypted, err := EncryptBytesAES([]byte(data), key)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

// EncryptBytesAES encrypts plainText with AES in CFB mode, using a random IV that is prepended to the result.
// The result is not authenticated, so it can be tampered with without being detected.
//
// Deprecated: AES-CFB is deprecated since Go 1.24. Use [github.com/zitadel/oidc/v3/pkg/op.NewAES256GCMCrypto]
// for new data, which encrypts with AES-256-GCM. Its output is in a different format, so keep
// [DecryptBytesAES] only to read data that was encrypted with this function.
func EncryptBytesAES(plainText []byte, key string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

// DecryptAES decodes base64url encoded data, without padding, and decrypts it with [DecryptBytesAES].
//
// Deprecated: AES-CFB is deprecated since Go 1.24. Use [github.com/zitadel/oidc/v3/pkg/op.NewAES256GCMCrypto]
// for new data, which encrypts with AES-256-GCM. Its output is in a different format, so keep
// using this function only to decrypt data that was encrypted by [EncryptAES].
func DecryptAES(data string, key string) (string, error) {
	text, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	decrypted, err := DecryptBytesAES(text, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// DecryptBytesAES decrypts cipherText that was encrypted by [EncryptBytesAES], using AES in CFB mode.
// The cipherText is not authenticated, so tampering with it is not detected.
//
// Deprecated: AES-CFB is deprecated since Go 1.24. Use [github.com/zitadel/oidc/v3/pkg/op.NewAES256GCMCrypto]
// for new data, which encrypts with AES-256-GCM. Its output is in a different format, so keep
// using this function only to decrypt data that was encrypted by [EncryptBytesAES].
func DecryptBytesAES(cipherText []byte, key string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, ErrCipherTextBlockSize
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return cipherText, err
}

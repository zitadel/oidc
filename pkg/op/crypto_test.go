package op

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAes256GCMCrypto_Ok(t *testing.T) {
	testCases := []struct {
		name  string
		key   string
		keyId string
		value string
	}{
		{
			name:  "happy flow",
			key:   "my-key-123456789-abcdefghijklmno",
			keyId: "key1",
			value: "Hello world",
		},
		{
			name:  "no key-id",
			key:   "my-key2-123456789-abcdefghijklmn",
			keyId: "",
			value: "Hello world",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cr := NewAES256GCMCrypto(NewBsKey(tc.key), tc.keyId)

			encrypted, err := cr.Encrypt(tc.value)
			require.NoError(t, err)

			decrypted, err := cr.Decrypt(encrypted)
			require.NoError(t, err)

			assert.Equal(t, tc.value, decrypted)
		})
	}
}

func TestCompositeCrypto(t *testing.T) {
	type TestCase struct {
		name       string
		encrypter  Encrypter
		decrypters []Decrypter
	}
	testCases := []TestCase{
		func() TestCase {
			aesGcmCrypto := NewAES256GCMCrypto(
				NewBsKey("my-key2-123456789-abcdefghijklmn"),
				"key1")
			return TestCase{
				name:       "same encrypter as decrypter",
				encrypter:  aesGcmCrypto,
				decrypters: []Decrypter{aesGcmCrypto},
			}
		}(),
		func() TestCase {
			aesGcmCrypto := NewAES256GCMCrypto(
				NewBsKey("my-key2-123456789-abcdefghijklmn"),
				"key1")
			return TestCase{
				name:      "one encrypter but two decrypters",
				encrypter: aesGcmCrypto,
				decrypters: []Decrypter{
					aesGcmCrypto,
					NewAESCrypto(NewBsKey("This_Key_Is_32_Bytes_Or_256_Bits")),
				},
			}
		}(),
		func() TestCase {
			aesCrypt := NewAESCrypto(NewBsKey("This_Key_Is_32_Bytes_Or_256_Bits"))
			return TestCase{
				name:      "one encrypter but two decrypters in other order",
				encrypter: aesCrypt,
				decrypters: []Decrypter{
					NewAES256GCMCrypto(
						NewBsKey("my-key2-123456789-abcdefghijklmn"),
						"key1"),
					aesCrypt,
				},
			}
		}(),
	}

	for _, tc := range testCases {
		const value = "My secret key"
		cr := NewCompositeCrypto(tc.encrypter, tc.decrypters)

		encrypted, err := cr.Encrypt(value)
		require.NoError(t, err)

		decrypted, err := cr.Decrypt(encrypted)
		require.NoError(t, err)

		assert.Equal(t, value, decrypted)
	}
}

func NewBsKey(key string) [32]byte {
	bs := [32]byte{}
	copy(bs[:], key)
	return bs
}

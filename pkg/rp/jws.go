package rp

import (
	"gopkg.in/square/go-jose.v2"
)

func CheckKey(keyID string, keys []jose.JSONWebKey, jws *jose.JSONWebSignature) ([]byte, error, bool) {
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			payload, err := jws.Verify(&key)
			return payload, err, true
		}
	}
	return nil, nil, false
}

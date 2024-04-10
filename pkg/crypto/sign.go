package crypto

import (
	"encoding/json"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
)

func Sign(object any, signer jose.Signer) (string, error) {
	payload, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	return SignPayload(payload, signer)
}

func SignPayload(payload []byte, signer jose.Signer) (string, error) {
	if signer == nil {
		return "", errors.New("missing signer")
	}
	result, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return result.CompactSerialize()
}

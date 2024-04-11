package op

import (
	"errors"

	jose "github.com/go-jose/go-jose/v4"
)

var ErrSignerCreationFailed = errors.New("signer creation failed")

type SigningKey interface {
	SignatureAlgorithm() jose.SignatureAlgorithm
	Key() any
	ID() string
}

func SignerFromKey(key SigningKey) (jose.Signer, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: key.SignatureAlgorithm(),
		Key: &jose.JSONWebKey{
			Key:   key.Key(),
			KeyID: key.ID(),
		},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, ErrSignerCreationFailed // TODO: log / wrap error?
	}
	return signer, nil
}

type Key interface {
	ID() string
	Algorithm() jose.SignatureAlgorithm
	Use() string
	Key() any
}

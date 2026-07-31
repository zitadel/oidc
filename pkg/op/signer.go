package op

import (
	"errors"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var ErrSignerCreationFailed = errors.New("signer creation failed")

type SigningKey interface {
	SignatureAlgorithm() jose.SignatureAlgorithm
	Key() any
	ID() string
}

func SignerFromKey(key SigningKey) (jose.Signer, error) {
	return SignerFromKeyAndType(key, oidc.IDTokenTypeJWT)
}

// SignerFromKeyAndType creates a signer with typ in the protected header.
func SignerFromKeyAndType(key SigningKey, typ jose.ContentType) (jose.Signer, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: key.SignatureAlgorithm(),
		Key: &jose.JSONWebKey{
			Key:   key.Key(),
			KeyID: key.ID(),
		},
	}, (&jose.SignerOptions{}).WithType(typ))
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

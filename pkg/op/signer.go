package op

import (
	"encoding/json"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type Signer interface {
	SignIDToken(claims *oidc.IDTokenClaims) (string, error)
	SignatureAlgorithm() jose.SignatureAlgorithm
}

type idTokenSigner struct {
	signer    jose.Signer
	storage   Storage
	algorithm jose.SignatureAlgorithm
}

func NewDefaultSigner(storage Storage) (Signer, error) {
	s := &idTokenSigner{
		storage: storage,
	}
	if err := s.initialize(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *idTokenSigner) initialize() error {
	key, err := s.storage.GetSigningKey()
	if err != nil {
		return err
	}
	s.signer, err = jose.NewSigner(*key, &jose.SignerOptions{})
	if err != nil {
		return err
	}
	s.algorithm = key.Algorithm
	return nil
}

func (s *idTokenSigner) SignIDToken(claims *oidc.IDTokenClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return s.Sign(payload)
}

func (s *idTokenSigner) Sign(payload []byte) (string, error) {
	result, err := s.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return result.CompactSerialize()
}

func (s *idTokenSigner) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.algorithm
}

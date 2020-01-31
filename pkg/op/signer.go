package op

import (
	"encoding/json"

	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

type Signer interface {
	SignIDToken(claims *oidc.IDTokenClaims) (string, error)
	SignAccessToken(claims *oidc.AccessTokenClaims) (string, error)
	SignatureAlgorithm() jose.SignatureAlgorithm
}

type idTokenSigner struct {
	signer    jose.Signer
	storage   AuthStorage
	algorithm jose.SignatureAlgorithm
}

func NewDefaultSigner(ctx context.Context, storage AuthStorage) (Signer, error) {
	s := &idTokenSigner{
		storage: storage,
	}
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *idTokenSigner) initialize(ctx context.Context) error {
	var key *jose.SigningKey
	var err error
	key, err = s.storage.GetSigningKey(ctx)
	if err != nil {
		key, err = s.storage.SaveKeyPair(ctx)
		if err != nil {
			return err
		}
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

func (s *idTokenSigner) SignAccessToken(claims *oidc.AccessTokenClaims) (string, error) {
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

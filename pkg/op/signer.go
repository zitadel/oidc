package op

import (
	"encoding/json"
	"errors"

	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/logging"
	"github.com/caos/oidc/pkg/oidc"
)

type Signer interface {
	Health(ctx context.Context) error
	SignIDToken(claims *oidc.IDTokenClaims) (string, error)
	SignAccessToken(claims *oidc.AccessTokenClaims) (string, error)
	SignatureAlgorithm() jose.SignatureAlgorithm
}

type tokenSigner struct {
	signer  jose.Signer
	storage AuthStorage
	alg     jose.SignatureAlgorithm
}

func NewDefaultSigner(ctx context.Context, storage AuthStorage, keyCh <-chan jose.SigningKey) Signer {
	s := &tokenSigner{
		storage: storage,
	}

	go s.refreshSigningKey(ctx, keyCh)

	return s
}

func (s *tokenSigner) Health(_ context.Context) error {
	if s.signer == nil {
		return errors.New("no signer")
	}
	return nil
}

func (s *tokenSigner) refreshSigningKey(ctx context.Context, keyCh <-chan jose.SigningKey) {
	for {
		select {
		case <-ctx.Done():
			return
		case key := <-keyCh:
			s.alg = key.Algorithm
			var err error
			s.signer, err = jose.NewSigner(key, &jose.SignerOptions{})
			logging.Log("OP-pf32aw").OnError(err).Error("error creating signer")
		}
	}
}

func (s *tokenSigner) SignIDToken(claims *oidc.IDTokenClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return s.Sign(payload)
}

func (s *tokenSigner) SignAccessToken(claims *oidc.AccessTokenClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return s.Sign(payload)
}

func (s *tokenSigner) Sign(payload []byte) (string, error) {
	result, err := s.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return result.CompactSerialize()
}

func (s *tokenSigner) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.alg
}

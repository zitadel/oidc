package op

import (
	"context"
	"errors"

	"github.com/caos/logging"
	"gopkg.in/square/go-jose.v2"
)

type Signer interface {
	Health(ctx context.Context) error
	//SignIDToken(claims *oidc.IDTokenClaims) (string, error)
	//SignAccessToken(claims *oidc.AccessTokenClaims) (string, error)
	Signer() jose.Signer
	SignatureAlgorithm() jose.SignatureAlgorithm
}

type tokenSigner struct {
	signer  jose.Signer
	storage AuthStorage
	alg     jose.SignatureAlgorithm
}

func NewSigner(ctx context.Context, storage AuthStorage, keyCh <-chan jose.SigningKey) Signer {
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

func (s *tokenSigner) Signer() jose.Signer {
	return s.signer
}

//
//func (s *tokenSigner) Sign(payload []byte) (*jose.JSONWebSignature, error) {
//	return s.signer.Sign(payload)
//}

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

func (s *tokenSigner) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.alg
}

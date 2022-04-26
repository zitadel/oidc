package op

import (
	"context"
	"errors"

	"github.com/zitadel/logging"
	"gopkg.in/square/go-jose.v2"
)

type Signer interface {
	Health(ctx context.Context) error
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

	select {
	case <-ctx.Done():
		return nil
	case key := <-keyCh:
		s.exchangeSigningKey(key)
	}
	go s.refreshSigningKey(ctx, keyCh)

	return s
}

func (s *tokenSigner) Health(_ context.Context) error {
	if s.signer == nil {
		return errors.New("no signer")
	}
	if string(s.alg) == "" {
		return errors.New("no signing algorithm")
	}
	return nil
}

func (s *tokenSigner) Signer() jose.Signer {
	return s.signer
}

func (s *tokenSigner) refreshSigningKey(ctx context.Context, keyCh <-chan jose.SigningKey) {
	for {
		select {
		case <-ctx.Done():
			return
		case key := <-keyCh:
			s.exchangeSigningKey(key)
		}
	}
}

func (s *tokenSigner) exchangeSigningKey(key jose.SigningKey) {
	s.alg = key.Algorithm
	if key.Algorithm == "" || key.Key == nil {
		s.signer = nil
		logging.Warn("signer has no key")
		return
	}
	var err error
	s.signer, err = jose.NewSigner(key, &jose.SignerOptions{})
	if err != nil {
		logging.New().WithError(err).Error("error creating signer")
		return
	}
	logging.Info("signer exchanged signing key")
}

func (s *tokenSigner) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.alg
}

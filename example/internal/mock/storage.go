package mock

import (
	"github.com/caos/oidc/pkg/oidc"
)

type Storage struct {
}

func (s *Storage) CreateAuthRequest(authReq *oidc.AuthRequest) error {
	return nil
}

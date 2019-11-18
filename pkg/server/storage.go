package server

import "github.com/caos/oidc/pkg/oidc"

type Storage interface {
	CreateAuthRequest(*oidc.AuthRequest) error
}

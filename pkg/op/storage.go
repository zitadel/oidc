package op

import "github.com/caos/oidc/pkg/oidc"

type Storage interface {
	CreateAuthRequest(*oidc.AuthRequest) error
	GetClientByClientID(string) (Client, error)
}

type Client interface {
	RedirectURIs() []string
	Type() ClientType
}

type ClientType int

func (c ClientType) IsConvidential() bool {
	return c == ClientTypeConfidential
}

const (
	ClientTypeConfidential ClientType = iota
	ClientTypePublic
)

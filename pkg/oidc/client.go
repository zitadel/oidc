package oidc

type Client interface {
	RedirectURIs() []string
	Type() ClientType
	LoginURL(string) string
}

type ClientType int

func (c ClientType) IsConvidential() bool {
	return c == ClientTypeConfidential
}

const (
	ClientTypeConfidential ClientType = iota
	ClientTypePublic
)

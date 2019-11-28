package oidc

type Client interface {
	RedirectURIs() []string
	ApplicationType() ApplicationType
	LoginURL(string) string
}

// type ClientType int

// func (c ClientType) IsConvidential() bool {
// 	return c == ClientTypeConfidential
// }

func IsConfidentialType(c Client) bool {
	return c.ApplicationType() == ApplicationTypeWeb
}

type ApplicationType int

// const (a ApplicationType)

const (
	// ClientTypeConfidential ClientType = iota
	// ClientTypePublic

	ApplicationTypeWeb ApplicationType = iota
	ApplicationTypeUserAgent
	ApplicationTypeNative
)

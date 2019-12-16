package op

const (
	ApplicationTypeWeb ApplicationType = iota
	ApplicationTypeUserAgent
	ApplicationTypeNative
)

type Client interface {
	GetID() string
	RedirectURIs() []string
	ApplicationType() ApplicationType
	GetAuthMethod() AuthMethod
	LoginURL(string) string
}

func IsConfidentialType(c Client) bool {
	return c.ApplicationType() == ApplicationTypeWeb
}

type ApplicationType int

type AuthMethod string

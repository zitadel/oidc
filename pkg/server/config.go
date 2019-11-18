package server

type Configuration interface {
	Issuer() string
	AuthorizationEndpoint() string
	TokenEndpoint() string
	UserinfoEndpoint() string
	Port() string
}

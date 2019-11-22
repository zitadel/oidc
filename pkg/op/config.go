package op

type Configuration interface {
	Issuer() string
	AuthorizationEndpoint() Endpoint
	TokenEndpoint() Endpoint
	UserinfoEndpoint() Endpoint
	Port() string
}

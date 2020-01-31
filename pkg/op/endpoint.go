package op

import "strings"

type Endpoint string

func (e Endpoint) Relative() string {
	return relativeEndpoint(string(e))
}

func (e Endpoint) Absolute(host string) string {
	return absoluteEndpoint(host, string(e))
}

func (e Endpoint) Validate() error {
	return nil //TODO:
}

func absoluteEndpoint(host, endpoint string) string {
	return strings.TrimSuffix(host, "/") + relativeEndpoint(endpoint)
}

func relativeEndpoint(endpoint string) string {
	return "/" + strings.TrimPrefix(endpoint, "/")
}

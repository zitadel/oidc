package op

import (
	"errors"
	"slices"
	"strings"
)

type Endpoint struct {
	method string
	path   string
	url    string
}

type EndpointOption func(endpoint *Endpoint)

func EndpointWithURL(url string) EndpointOption {
	return func(endpoint *Endpoint) {
		endpoint.url = url
	}
}

func EndpointWithMethod(method string) EndpointOption {
	return func(endpoint *Endpoint) {
		endpoint.method = method
	}
}

func NewEndpoint(path string, opts ...EndpointOption) *Endpoint {
	endpoint := &Endpoint{path: path}

	for option := range slices.Values(opts) {
		option(endpoint)
	}

	return endpoint
}

func NewEndpointWithURL(path, url string) *Endpoint {
	return &Endpoint{path: path, url: url}
}

func (e *Endpoint) Method() string {
	if e == nil {
		return ""
	}

	return e.method
}

func (e *Endpoint) Relative() string {
	if e == nil {
		return ""
	}
	return relativeEndpoint(e.path)
}

func (e *Endpoint) Absolute(host string) string {
	if e == nil {
		return ""
	}
	if e.url != "" {
		return e.url
	}
	return absoluteEndpoint(host, e.path)
}

var ErrNilEndpoint = errors.New("nil endpoint")

func (e *Endpoint) Validate() error {
	if e == nil {
		return ErrNilEndpoint
	}
	return nil // TODO:
}

func absoluteEndpoint(host, endpoint string) string {
	return strings.TrimSuffix(host, "/") + relativeEndpoint(endpoint)
}

func relativeEndpoint(endpoint string) string {
	return "/" + strings.TrimPrefix(endpoint, "/")
}

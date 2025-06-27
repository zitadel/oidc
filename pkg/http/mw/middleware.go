package mw

import (
	"net/http"
	"slices"
)

type Middleware = func(http.Handler) http.Handler

type Chain struct {
	*http.ServeMux

	chain []Middleware
}

func New() *Chain {
	return NewWithServeMux(http.NewServeMux())
}
func NewWithServeMux(mx *http.ServeMux) *Chain {
	return &Chain{ServeMux: mx}
}

func (c *Chain) Use(mw ...Middleware) {
	c.chain = append(c.chain, mw...)
}

func (c *Chain) Handle(pattern string, handler http.Handler) {
	out := handler
	for _, mw := range slices.Backward(c.chain) {
		out = mw(out)
	}

	c.ServeMux.Handle(pattern, out)
}

func (c *Chain) HandleFunc(pattern string, handler http.HandlerFunc) {
	c.Handle(pattern, handler)
}

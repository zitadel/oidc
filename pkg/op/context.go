package op

import (
	"context"
	"net/http"
)

type key int

const (
	issuerKey key = 0
)

type IssuerInterceptor struct {
	issuerFromRequest IssuerFromRequest
}

// NewIssuerInterceptor will set the issuer into the context
// by the provided IssuerFromRequest (e.g. returned from StaticIssuer or IssuerFromHost)
func NewIssuerInterceptor(issuerFromRequest IssuerFromRequest) *IssuerInterceptor {
	return &IssuerInterceptor{
		issuerFromRequest: issuerFromRequest,
	}
}

func (i *IssuerInterceptor) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.setIssuerCtx(w, r, next)
	})
}

func (i *IssuerInterceptor) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		i.setIssuerCtx(w, r, next)
	}
}

// IssuerFromContext reads the issuer from the context (set by an IssuerInterceptor)
// it will return an empty string if not found
func IssuerFromContext(ctx context.Context) string {
	ctxIssuer, _ := ctx.Value(issuerKey).(string)
	return ctxIssuer
}

// ContextWithIssuer returns a new context with issuer set to it.
func ContextWithIssuer(ctx context.Context, issuer string) context.Context {
	return context.WithValue(ctx, issuerKey, issuer)
}

func (i *IssuerInterceptor) setIssuerCtx(w http.ResponseWriter, r *http.Request, next http.Handler) {
	r = r.WithContext(ContextWithIssuer(r.Context(), i.issuerFromRequest(r)))
	next.ServeHTTP(w, r)
}

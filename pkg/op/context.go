package op

import (
	"context"
	"net/http"
)

type key int

var (
	issuer key = 0
)

type IssuerInterceptor struct {
	issuerFromRequest IssuerFromRequest
}

//NewIssuerInterceptor will set the issuer into the context
//by the provided IssuerFromRequest (e.g. returned from StaticIssuer or IssuerFromHost)
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

//IssuerFromContext reads the issuer from the context (set by an IssuerInterceptor)
//it will return an empty string if not found
func IssuerFromContext(ctx context.Context) string {
	ctxIssuer, _ := ctx.Value(issuer).(string)
	return ctxIssuer
}

func (i *IssuerInterceptor) setIssuerCtx(w http.ResponseWriter, r *http.Request, next http.Handler) {
	ctx := context.WithValue(r.Context(), issuer, i.issuerFromRequest(r))
	r = r.WithContext(ctx)
	next.ServeHTTP(w, r)
}

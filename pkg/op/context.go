package op

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

type key int

const (
	issuerKey key = iota
	tenantKey
	metadataMatchKey
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

// TenantFromContext reads the tenant from the context.
// It returns an empty string if none was set.
//
// The tenant is the single path segment that identifies an issuer
// in a multi-tenant deployment, after an optional static prefix.
// For the issuer https://op.example.com/oauth/p1 with the prefix
// "/oauth", the tenant is "p1". It is set only by [WithTenantPrefix], on a
// [RegisterServer] handler and on a [MetadataHandler] for the well-known
// paths, so an [IssuerInterceptor] that reads it sees the same value for
// both. Without that option no tenant is set. With it, the tenant is
// also empty for a request to the prefix itself,
// https://op.example.com/oauth, which the implementation may serve as an
// issuer of its own or refuse. The tenant is not the full issuer path; a
// [MetadataRequest] carries that as IssuerPath.
//
// EXPERIMENTAL: may change until v4
func TenantFromContext(ctx context.Context) string {
	tenant, _ := ctx.Value(tenantKey).(string)
	return tenant
}

// ContextWithTenant returns a new context with tenant set to it.
//
// EXPERIMENTAL: may change until v4
func ContextWithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey, tenant)
}

// routeSource returns the string chi would route the request on,
// as [chi.Mux] does: the route path when chi set it, otherwise the URL's
// raw path when it has one, otherwise the URL path. escaped reports
// whether that string is percent-encoded. A route path set by a chi Mount
// is a suffix of the raw path and is encoded; one that a middleware such
// as chi's StripSlashes or URLFormat built from the decoded URL path is
// not, even when the URL has a raw path. The route path is taken as
// encoded only when it is a suffix of the raw path, allowing for a
// stripped trailing slash. rctx is the chi route context when the route
// path was used.
func routeSource(r *http.Request) (src string, escaped bool, rctx *chi.Context) {
	raw := r.URL.RawPath
	if rctx = chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
		routePath := rctx.RoutePath
		escaped = raw != "" && (strings.HasSuffix(raw, routePath) || strings.HasSuffix(raw, routePath+"/"))
		return routePath, escaped, rctx
	}
	if raw != "" {
		return raw, true, nil
	}
	return r.URL.Path, false, nil
}

// routedPath returns the path chi would route the request on,
// percent-decoded exactly once. See [routeSource].
func routedPath(r *http.Request) (string, error) {
	src, escaped, _ := routeSource(r)
	return decodeRouteSource(src, escaped)
}

// decodeRouteSource returns src from [routeSource],
// percent-decoded exactly once when it is escaped.
func decodeRouteSource(src string, escaped bool) (string, error) {
	if !escaped {
		return src, nil
	}
	return url.PathUnescape(src)
}

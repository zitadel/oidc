package op

import (
	"context"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// MetadataServer serves the OpenID Provider Configuration and the
// OAuth 2.0 Authorization Server Metadata from their well-known paths.
// Where [Server.Discovery] answers only the well-known path directly
// under the handler, a MetadataServer registered with
// [RegisterMetadataServer] serves every URL form the standards define
// for an issuer with a path, including RFC 8414 section 5.
//
// The Request's Data carries the issuer path found in the URL as
// [MetadataRequest]; the tenant derived from it is on the context,
// see [TenantFromContext]. An implementation that serves more than one
// issuer builds its response from these, and should answer with a
// 404 when the issuer path does not name an issuer it serves, as
// RFC 8414 section 3.3 asks.
//
// A response that depends on the request origin, for example an issuer
// taken from a forwarded host, should set "Cache-Control: private" or a
// Vary header through [Response.Header], so a shared cache does not hand
// it to another origin.
//
// The addition of new methods is not considered a breaking change
// as defined by semver rules.
// Implementations MUST embed [UnimplementedMetadataServer] to maintain
// forward compatibility.
//
// EXPERIMENTAL: may change until v4
type MetadataServer interface {
	// OpenIDConfiguration returns the OpenID Provider Configuration Information
	// for the issuer named by the request.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	// The recommended Response Data type is [oidc.DiscoveryConfiguration].
	OpenIDConfiguration(context.Context, *Request[MetadataRequest]) (*Response, error)

	// AuthorizationServerMetadata returns the OAuth 2.0 Authorization Server
	// Metadata for the issuer named by the request.
	// https://datatracker.ietf.org/doc/html/rfc8414#section-3
	// The recommended Response Data type is [oidc.DiscoveryConfiguration].
	AuthorizationServerMetadata(context.Context, *Request[MetadataRequest]) (*Response, error)

	// mustImplMetadata forces implementations to embed the
	// UnimplementedMetadataServer for forward compatibility with the interface.
	mustImplMetadata()
}

// MetadataRequest is the Data of a [MetadataServer] request.
//
// EXPERIMENTAL: may change until v4
type MetadataRequest struct {
	// IssuerPath is the path of the issuer as it was found in the
	// well-known URL, percent-decoded once and without a trailing slash.
	// It is "" for an issuer without a path, or starts with a slash,
	// for example "/a" or "/a/b". This is the full issuer path; with
	// [WithTenantPrefix], the tenant on the context is the single routing
	// segment inside it, see [TenantFromContext].
	IssuerPath string
}

// UnimplementedMetadataServer is the base implementation of [MetadataServer]
// which returns an unimplemented error for each of its methods.
// Implementations MUST embed it for forward compatibility.
//
// EXPERIMENTAL: may change until v4
type UnimplementedMetadataServer struct{}

func (UnimplementedMetadataServer) mustImplMetadata() {}

func (UnimplementedMetadataServer) OpenIDConfiguration(ctx context.Context, r *Request[MetadataRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedMetadataServer) AuthorizationServerMetadata(ctx context.Context, r *Request[MetadataRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

// MetadataHandler serves a [MetadataServer] over HTTP.
// It is created by [RegisterMetadataServer].
//
// EXPERIMENTAL: may change until v4
type MetadataHandler struct {
	server       MetadataServer
	handler      http.Handler
	tenantPrefix string
	tenantSet    bool
}

// RegisterMetadataServer registers an implementation of [MetadataServer].
// The resulting handler parses the well-known path itself, so it has to
// be mounted at the root of the issuer's host. It serves, in this order
// of precedence, with P the issuer path ("" or starting with a slash):
//
//	/.well-known/oauth-authorization-server{P}   RFC 8414 section 3
//	/.well-known/openid-configuration{P}         RFC 8414 section 5, P = "" is OpenID Discovery for a pathless issuer
//	{P}/.well-known/openid-configuration         OpenID Connect Discovery section 4, P != ""
//
// Any other path, an issuer path with a trailing slash, an empty or a
// dot segment, and, with [WithTenantPrefix] set, an issuer path other
// than "{prefix}" (the empty tenant) or "{prefix}/{tenant}" are a 404.
// Without the option, every valid issuer path is served and no tenant is
// set; see [WithTenantPrefix] for how the tenant is derived. Only GET and HEAD are served; other
// methods get a 405 with an Allow header. CORS preflights are answered
// before the routes.
//
// The path is the one chi routes on, percent-decoded once: the route
// path set by a chi Mount at the root, otherwise the URL path. Under a
// [http.ServeMux], register the handler for "/.well-known/" and for the
// OpenID form, "{prefix}/{tenant}/.well-known/openid-configuration".
// The patterns "/.well-known/" and "/{tenant}/.well-known/" conflict and
// panic at registration, so without a static prefix in front of the
// tenant, use [MetadataHandler.Intercept] in front of the mux instead.
//
// The tenant of the issuer path is set on the request context before the
// middleware of [WithHTTPMiddleware] runs, so an [IssuerInterceptor] whose
// IssuerFromRequest reads [TenantFromContext] works the same here and on
// a [RegisterServer] handler with the same [WithTenantPrefix].
//
// The options are shared with [RegisterServer]: [WithServerCORSOptions],
// [WithHTTPMiddleware], [WithSetRouter] and [WithTenantPrefix] apply.
// [WithDecoder] and [WithEncoder] have no effect, as no request body or
// error redirect is handled. The router's MethodNotAllowed handler and
// its single "/*" route are set after the options are applied, so
// [WithSetRouter] cannot replace them; a "/*" route or a MethodNotAllowed
// handler set there is overwritten.
//
// EXPERIMENTAL: may change until v4
func RegisterMetadataServer(server MetadataServer, options ...ServerOption) *MetadataHandler {
	corsOpts := cloneCORSOptions(defaultCORSOptions)
	ws := &webServer{
		router:   chi.NewRouter(),
		corsOpts: &corsOpts,
	}
	for _, option := range options {
		option(ws)
	}

	h := &MetadataHandler{
		server:       server,
		tenantPrefix: ws.tenantPrefix,
		tenantSet:    ws.tenantSet,
	}
	// chi answers a method it does not know itself, before the route runs.
	ws.router.MethodNotAllowed(h.methodNotAllowed)
	ws.router.HandleFunc("/*", h.handle)
	ws.wrapCORS(ws.router)
	h.handler = ws.handler
	return h
}

// ServeHTTP serves a request to a well-known path.
// A path that does not match is answered with a 404.
func (h *MetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A no-match is served through the CORS wrapper and the middleware
	// too, so a browser sees the 404 and not a CORS failure.
	m, _ := h.match(r)
	h.serve(w, r, m)
}

// Intercept returns a handler that serves the well-known paths
// and passes every other request on to next.
// This allows the metadata handler to sit in front of a mux whose
// patterns would conflict with the well-known paths.
func (h *MetadataHandler) Intercept(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, ok := h.match(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		h.serve(w, r, m)
	})
}

// metadataMatch is the result of matching a request path
// against the well-known path forms.
type metadataMatch struct {
	method     func(MetadataServer, context.Context, *Request[MetadataRequest]) (*Response, error)
	issuerPath string
	tenant     string
}

func (h *MetadataHandler) match(r *http.Request) (*metadataMatch, bool) {
	reqPath, err := routedPath(r)
	if err != nil {
		return nil, false
	}
	method, issuerPath, ok := matchMetadataPath(reqPath)
	if !ok {
		return nil, false
	}
	tenant, ok := tenantFromIssuerPath(h.tenantPrefix, h.tenantSet, issuerPath)
	if !ok {
		return nil, false
	}
	return &metadataMatch{
		method:     method,
		issuerPath: issuerPath,
		tenant:     tenant,
	}, true
}

// serve runs the inner handler (CORS, middleware, router) for the
// request. m is nil when the path did not match; the route then
// answers with a 404.
func (h *MetadataHandler) serve(w http.ResponseWriter, r *http.Request, m *metadataMatch) {
	ctx := r.Context()
	if m != nil {
		ctx = ContextWithTenant(ctx, m.tenant)
		ctx = context.WithValue(ctx, metadataMatchKey, m)
	}
	h.handler.ServeHTTP(w, r.WithContext(ctx))
}

// matchFromContext returns the match serve put on the context,
// or nil when the path did not match.
func matchFromContext(ctx context.Context) *metadataMatch {
	m, _ := ctx.Value(metadataMatchKey).(*metadataMatch)
	return m
}

func writeMetadataNotFound(w http.ResponseWriter, r *http.Request) {
	writeNotFound(w, r, "no metadata at this path")
}

// methodNotAllowed answers every method but GET and HEAD. It is the
// router's MethodNotAllowed handler, for methods chi does not know, and
// is called by handle for the ones chi knows.
func (h *MetadataHandler) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if matchFromContext(r.Context()) == nil {
		writeMetadataNotFound(w, r)
		return
	}
	w.Header().Set("Allow", "GET, HEAD")
	err := oidc.ErrInvalidRequest().WithDescription("method not allowed")
	WriteError(w, r, NewStatusError(err, http.StatusMethodNotAllowed), nil)
}

// handle is the single route of the handler's router. It runs after
// CORS and the user middleware, with the match on the context.
func (h *MetadataHandler) handle(w http.ResponseWriter, r *http.Request) {
	m := matchFromContext(r.Context())
	if m == nil {
		writeMetadataNotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.methodNotAllowed(w, r)
		return
	}
	serveSimple(w, r, &MetadataRequest{IssuerPath: m.issuerPath},
		func(ctx context.Context, req *Request[MetadataRequest]) (*Response, error) {
			return m.method(h.server, ctx, req)
		},
	)
}

// matchMetadataPath matches the decoded request path against the
// well-known path forms and returns the method to call and the issuer path.
func matchMetadataPath(reqPath string) (method func(MetadataServer, context.Context, *Request[MetadataRequest]) (*Response, error), issuerPath string, ok bool) {
	if p, found := strings.CutPrefix(reqPath, oidc.AuthorizationServerMetadataEndpoint); found && validIssuerPath(p) {
		return MetadataServer.AuthorizationServerMetadata, p, true
	}
	if p, found := strings.CutPrefix(reqPath, oidc.DiscoveryEndpoint); found && validIssuerPath(p) {
		return MetadataServer.OpenIDConfiguration, p, true
	}
	if p, found := strings.CutSuffix(reqPath, oidc.DiscoveryEndpoint); found && p != "" && validIssuerPath(p) {
		return MetadataServer.OpenIDConfiguration, p, true
	}
	return nil, "", false
}

// validIssuerPath reports whether p is "" or a path that starts with
// a slash, has no trailing slash and no empty or dot segment, which is
// exactly a non-root path that [path.Clean] leaves as it is.
func validIssuerPath(p string) bool {
	return p == "" || (p != "/" && p[0] == '/' && path.Clean(p) == p)
}

// tenantFromIssuerPath derives the tenant from a valid issuer path.
// With [WithTenantPrefix] set, with any prefix including "", the issuer
// path must be exactly "{prefix}", for the empty tenant, or
// "{prefix}/{tenant}"; ok is false otherwise. Without the option, every
// issuer path is accepted and no tenant is derived.
func tenantFromIssuerPath(prefix string, set bool, issuerPath string) (tenant string, ok bool) {
	if !set {
		return "", true
	}
	if issuerPath == prefix {
		return "", true
	}
	rest, found := strings.CutPrefix(issuerPath, prefix+"/")
	if !found || rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

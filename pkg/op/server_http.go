package op

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/schema"
)

// RegisterServer registers an implementation of Server.
// The resulting handler takes care of routing and request parsing,
// with some basic validation of required fields.
// The routes can be customized with [WithEndpoints].
//
// EXPERIMENTAL: may change until v4
func RegisterServer(server Server, endpoints Endpoints, options ...ServerOption) http.Handler {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	corsOpts := cloneCORSOptions(defaultCORSOptions)
	ws := &webServer{
		router:    chi.NewRouter(),
		server:    server,
		endpoints: endpoints,
		decoder:   decoder,
		encoder:   oidc.NewEncoder(),
		corsOpts:  &corsOpts,
	}

	for _, option := range options {
		option(ws)
	}

	ws.createRouter()
	var inner http.Handler = ws.router
	if ws.tenantSet {
		// Inside CORS, so a tenant 404 carries CORS headers, and before the
		// router, so its middleware sees the tenant and routes on the
		// stripped path.
		inner = ws.stripTenant(ws.router)
	}
	ws.wrapCORS(inner)
	return ws
}

// wrapCORS sets the handler to inner,
// wrapped with the CORS policy when one is set.
func (s *webServer) wrapCORS(inner http.Handler) {
	s.handler = inner
	if s.corsOpts != nil {
		s.handler = cors.New(*s.corsOpts).Handler(inner)
	}
}

type ServerOption func(s *webServer)

// WithHTTPMiddleware sets the passed middleware chain to the root of
// the Server's router.
func WithHTTPMiddleware(m ...func(http.Handler) http.Handler) ServerOption {
	return func(s *webServer) {
		s.router.Use(m...)
	}
}

// WithSetRouter allows customization or the Server's router.
func WithSetRouter(set func(chi.Router)) ServerOption {
	return func(s *webServer) {
		set(s.router)
	}
}

// WithDecoder overrides the default decoder,
// which is a [schema.Decoder] with IgnoreUnknownKeys set to true.
func WithDecoder(decoder httphelper.Decoder) ServerOption {
	return func(s *webServer) {
		s.decoder = decoder
	}
}

// WithEncoder overrides the default encoder,
// which is an [oidc.NewEncoder].
// It is used to build the error redirect an authorization request
// is answered with when it fails after its redirect_uri was validated.
func WithEncoder(encoder httphelper.Encoder) ServerOption {
	return func(s *webServer) {
		s.encoder = encoder
	}
}

// WithServerCORSOptions sets the CORS policy for the Server's router.
func WithServerCORSOptions(opts *cors.Options) ServerOption {
	return func(s *webServer) {
		s.corsOpts = opts
	}
}

// WithFallbackLogger is retained for source compatibility.
// Deprecated: use [slog.SetDefault]. This option has no effect.
func WithFallbackLogger(*slog.Logger) ServerOption {
	return func(*webServer) {
	}
}

// WithTenantPrefix serves one handler for many issuers that differ in
// one path segment, the tenant: https://op.example.com{prefix}/{tenant}.
// With the prefix "/oauth", the issuer path "/oauth/p1" has the tenant
// "p1", which is set on the request context, see [TenantFromContext].
// A missing leading slash or a trailing slash on prefix is tolerated,
// and "/" is the same as "".
//
// For a [RegisterServer] handler, the request path must be "{prefix}" or
// start with "{prefix}/"; any other path is answered with a 404 that
// carries the CORS headers. The prefix is stripped and the rest of the
// path is read as follows:
//
//   - If it matches a route of the handler's own router, with any
//     standard method, the tenant is "" and nothing more is stripped,
//     so "/oauth/authorize" is the authorization endpoint of the empty
//     tenant. The router's routes include those added with [WithSetRouter].
//     A wrong method on such a route gets the router's 405.
//   - Otherwise its first segment is the tenant and is stripped too, so
//     "/oauth/p1/authorize" is the authorization endpoint of tenant "p1".
//     A tenant segment of "." or ".." is a 404.
//   - "{prefix}" and "{prefix}/" give the tenant "" and the path "/",
//     which the router answers as it would.
//
// The tenant is set on the context before the handler's middleware and
// routes run, so an [IssuerInterceptor] added with [WithHTTPMiddleware]
// sees it. The empty tenant is for the implementation to interpret: as an
// issuer of its own at https://op.example.com/oauth, or refused. With the
// prefix "", the first segment is the tenant. Without this option,
// RegisterServer does no tenant handling and serves its routes at its
// root, as before.
//
// The route check and the tenant split run on the path as received,
// before the middleware of [WithHTTPMiddleware]. Middleware that rewrites
// the path, such as chi's middleware.StripSlashes, must therefore wrap
// the handler from outside or run on the parent router. Added through
// [WithHTTPMiddleware] it runs too late: "/oauth/healthz/" is then read
// as tenant "healthz" with the path "/".
//
// Because a known route wins, a tenant T loses its route R when "/T"+R is
// itself a route of the handler, and loses its bare root "{prefix}/T"
// when "/T" is a route. With the endpoints "/a" and "/b/a", "/oauth/b/a"
// is the empty tenant's "/b/a", so tenant "b" has no "/a". With the
// default endpoints, a tenant named "authorize" loses only its root,
// "/oauth/authorize", which is the empty tenant's authorization endpoint,
// and keeps "/oauth/authorize/keys" and the rest. A catch-all such as
// "/*" added through [WithSetRouter] matches every path, so every request
// gets the empty tenant. Opaque tenant IDs, such as random IDs, avoid
// both.
//
// For a [RegisterMetadataServer] handler with this option, with any
// prefix including "", the issuer path must be exactly "{prefix}", for
// the empty tenant, or "{prefix}/{tenant}"; any other issuer path, such as
// a multi-segment one, is a 404 and the [MetadataServer] is not called.
// Without the option, every valid issuer path is passed to the server as
// [MetadataRequest.IssuerPath] and no tenant is set.
//
// Both handlers take the same prefix when the OP handler receives the
// full request path: on a [http.ServeMux] with mux.Handle("/oauth/", h)
// and no [http.StripPrefix], or on chi with r.Handle("/oauth/*", h):
//
//	meta := op.RegisterMetadataServer(ms, op.WithTenantPrefix("/oauth"), op.WithHTTPMiddleware(issuerMW))
//	srv := op.RegisterServer(s, ep, op.WithTenantPrefix("/oauth"), op.WithHTTPMiddleware(issuerMW))
//	mux.Handle("/.well-known/", meta)
//	mux.Handle("/oauth/{t}/.well-known/openid-configuration", meta)
//	mux.Handle("/oauth/.well-known/openid-configuration", meta)
//	mux.Handle("/oauth/", srv)
//
// The third pattern is the OpenID Connect Discovery form of the empty
// tenant's issuer, https://op.example.com/oauth. Without it, that path
// reaches the OP handler, where "/.well-known/openid-configuration" is
// the known [Server.Discovery] route of the empty tenant.
//
// Under chi's r.Mount("/oauth", h), chi strips the mount prefix before
// the handler runs, so the OP handler takes [WithTenantPrefix] with "".
//
// The path is the one chi routes on, decoded once before it is split
// into segments. A percent-encoded slash therefore splits segments too;
// when it is the slash that ends the tenant, the request is refused with
// a 404 rather than guessing where the tenant ends.
//
// EXPERIMENTAL: may change until v4
func WithTenantPrefix(prefix string) ServerOption {
	return func(s *webServer) {
		s.tenantPrefix = normalizeTenantPrefix(prefix)
		s.tenantSet = true
	}
}

// normalizeTenantPrefix drops trailing slashes and adds the leading one,
// so that "oauth", "/oauth/" and "/oauth" are the same prefix and "/" is
// the same as no prefix.
func normalizeTenantPrefix(prefix string) string {
	prefix = strings.TrimRight(prefix, "/")
	if prefix != "" && !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return prefix
}

// isDotSegment reports whether segment is "." or "..",
// which never name a tenant or an issuer.
func isDotSegment(segment string) bool {
	return segment == "." || segment == ".."
}

// orRoot returns "/" for an empty path, so that a path
// that was stripped to nothing still routes as the root.
func orRoot(path string) string {
	return cmp.Or(path, "/")
}

// standardMethods are the methods chi routes. A path that matches a
// route for any of them is a known route, so that a request with the
// wrong method gets the router's 405 instead of being read as a tenant.
var standardMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

// knownRoute reports whether path matches a route of the router,
// for method or for any standard method.
func (s *webServer) knownRoute(method, path string) bool {
	rctx := chi.NewRouteContext()
	if s.router.Match(rctx, method, path) {
		return true
	}
	for _, m := range standardMethods {
		if m == method {
			continue
		}
		rctx.Reset()
		if s.router.Match(rctx, m, path) {
			return true
		}
	}
	return false
}

// stripTenant implements [WithTenantPrefix] for a [RegisterServer]
// handler. The path must be the prefix or start with it; the rest of the
// path is the router's path when it is a known route, with the tenant "",
// and "{tenant}{path}" otherwise, see [WithTenantPrefix]. The tenant is
// set on the request context and the prefix and the tenant are stripped
// from the path before next is called. A path outside the prefix is
// answered with a 404 and next is not called.
//
// The path is the one chi routes on: the route path set by a chi Mount,
// or else the URL path, decoded once before it is split into segments.
// A percent-encoded slash therefore splits segments too; when it is the
// slash that ends the prefix or the tenant, the request is refused with
// a 404 rather than guessing where they end. The route check uses the
// encoding chi routes on, the raw path when the source is escaped. When
// chi's route path is set, it is updated in place. Otherwise the request
// is cloned with the stripped URL path and raw path, as [http.StripPrefix]
// does.
func (s *webServer) stripTenant(next http.Handler) http.Handler {
	prefix := s.tenantPrefix
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		src, escaped, rctx := routeSource(r)
		path, err := decodeRouteSource(src, escaped)
		if err != nil {
			writeTenantNotFound(w, r)
			return
		}

		// rest is the decoded path after the prefix, at least "/".
		rest := "/"
		if path != prefix {
			after, ok := strings.CutPrefix(path, prefix+"/")
			if !ok {
				writeTenantNotFound(w, r)
				return
			}
			rest += after
		}
		// restRaw is rest in the encoding chi routes on.
		restRaw := rest
		if escaped {
			restRaw = orRoot(src[rawOffset(src, len(prefix)):])
			if restRaw[0] != '/' {
				// The slash that ends the prefix is percent-encoded.
				writeTenantNotFound(w, r)
				return
			}
		}

		tenant := ""
		stripped, strippedRaw := rest, restRaw
		if !s.knownRoute(r.Method, restRaw) {
			tenant, _, _ = strings.Cut(rest[1:], "/")
			if isDotSegment(tenant) || (tenant == "" && rest != "/") {
				// A dot segment, or an empty segment followed by more path.
				writeTenantNotFound(w, r)
				return
			}
			if tenant != "" {
				n := 1 + len(tenant)
				stripped = orRoot(rest[n:])
				strippedRaw = stripped
				if escaped {
					strippedRaw = restRaw[rawOffset(restRaw, n):]
					if strippedRaw != "" && strippedRaw[0] != '/' {
						// The slash that ends the tenant is percent-encoded, so the
						// decoded and the raw path disagree on where the tenant ends.
						writeTenantNotFound(w, r)
						return
					}
					strippedRaw = orRoot(strippedRaw)
				}
			}
		}

		r = r.WithContext(ContextWithTenant(r.Context(), tenant))
		if rctx != nil {
			rctx.RoutePath = strippedRaw
			next.ServeHTTP(w, r)
			return
		}
		u := new(url.URL)
		*u = *r.URL
		u.Path = stripped
		if u.RawPath != "" {
			u.RawPath = strippedRaw
		}
		r.URL = u
		next.ServeHTTP(w, r)
	})
}

func writeTenantNotFound(w http.ResponseWriter, r *http.Request) {
	writeNotFound(w, r, "path is not under the tenant prefix")
}

// writeNotFound writes a JSON 404 with an invalid_request error
// carrying description.
func writeNotFound(w http.ResponseWriter, r *http.Request, description string) {
	err := oidc.ErrInvalidRequest().WithDescription("%s", description)
	WriteError(w, r, NewStatusError(err, http.StatusNotFound), nil)
}

type webServer struct {
	server    Server
	router    *chi.Mux
	handler   http.Handler
	endpoints Endpoints
	decoder   httphelper.Decoder
	encoder   httphelper.Encoder
	corsOpts  *cors.Options

	// tenantPrefix is the normalized prefix of WithTenantPrefix and
	// tenantSet whether the option was given. RegisterServer strips the
	// tenant only when it was; a MetadataHandler uses the prefix either way.
	tenantPrefix string
	tenantSet    bool
}

func (s *webServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *webServer) createRouter() {
	s.router.HandleFunc(healthEndpoint, simpleHandler(s, s.server.Health))
	s.router.HandleFunc(readinessEndpoint, simpleHandler(s, s.server.Ready))
	s.router.HandleFunc(oidc.DiscoveryEndpoint, simpleHandler(s, s.server.Discovery))

	s.endpointRoute(s.endpoints.Authorization, s.authorizeHandler)
	s.endpointRoute(s.endpoints.DeviceAuthorization, s.withClient(s.deviceAuthorizationHandler))
	s.endpointRoute(s.endpoints.Token, s.tokensHandler)
	s.endpointRoute(s.endpoints.Introspection, s.introspectionHandler)
	s.endpointRoute(s.endpoints.Userinfo, s.userInfoHandler)
	s.endpointRoute(s.endpoints.Revocation, s.withClient(s.revocationHandler))
	s.endpointRoute(s.endpoints.EndSession, s.endSessionHandler)
	s.endpointRoute(s.endpoints.JwksURI, simpleHandler(s, s.server.Keys))
}

func (s *webServer) endpointRoute(e *Endpoint, hf http.HandlerFunc) {
	if e != nil {
		traceHandler := func(w http.ResponseWriter, r *http.Request) {
			ctx, span := Tracer.Start(r.Context(), e.Relative())
			r = r.WithContext(ctx)
			hf(w, r)
			defer span.End()
		}
		s.router.HandleFunc(e.Relative(), traceHandler)
		slog.Info("registered route", "endpoint", e.Relative())
	}
}

type clientHandler func(w http.ResponseWriter, r *http.Request, client Client)

func (s *webServer) withClient(handler clientHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := Tracer.Start(r.Context(), r.URL.Path)
		defer span.End()
		r = r.WithContext(ctx)

		client, err := s.verifyRequestClient(r)
		if err != nil {
			WriteError(w, r, err, nil)
			return
		}
		if grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType != "" {
			if !ValidateGrantType(client, grantType) {
				WriteError(w, r, oidc.ErrUnauthorizedClient().WithDescription("grant_type %q not allowed", grantType), nil)
				return
			}
		}
		handler(w, r, client)
	}
}

func (s *webServer) verifyRequestClient(r *http.Request) (_ Client, err error) {
	cc, err := s.parseClientCredentials(r)
	if err != nil {
		return nil, err
	}
	return s.server.VerifyClient(r.Context(), &Request[ClientCredentials]{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		Form:   r.Form,
		Data:   cc,
	})
}

func (s *webServer) parseClientCredentials(r *http.Request) (_ *ClientCredentials, err error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	cc := new(ClientCredentials)
	if err = s.decoder.Decode(cc, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
	// The client MUST NOT use more than one authentication method in each request.
	assertionAuthExists := cc.ClientAssertion != "" && cc.ClientAssertionType != ""
	secretAuthExists := cc.ClientSecret != "" && cc.ClientID != ""
	if assertionAuthExists && secretAuthExists {
		return nil, oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method")
	}

	// Basic auth takes precedence, so if set it overwrites the form data.
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		if assertionAuthExists || secretAuthExists {
			return nil, oidc.ErrInvalidRequest().WithDescription("client authentication must not use more than one method")
		}
		cc.ClientID, err = url.QueryUnescape(clientID)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
		cc.ClientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
	}
	if cc.ClientID == "" && cc.ClientAssertion == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_id or client_assertion must be provided")
	}
	if cc.ClientAssertion != "" && cc.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion {
		return nil, oidc.ErrInvalidRequest().WithDescription("invalid client_assertion_type %s", cc.ClientAssertionType)
	}
	return cc, nil
}

func (s *webServer) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.AuthRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	redirect, err := s.authorize(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	redirect.writeOut(w, r)
}

func (s *webServer) authorize(ctx context.Context, r *Request[oidc.AuthRequest]) (*Redirect, error) {
	cr, err := s.server.VerifyAuthRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	authReq := cr.Data
	if authReq.RedirectURI == "" {
		// Redirect-disabled, so that this refusal stays un-reflected by
		// construction and not merely by where it is raised.
		return nil, oidc.ErrInvalidRequestRedirectURI().
			WithParent(ErrAuthReqMissingRedirectURI).
			WithDescription(authReqMissingRedirectURI)
	}
	// The redirect_uri is validated before any policy check, the order
	// ValidateAuthRequestClient uses. Every check after this one therefore runs
	// against a redirect_uri the client has registered, which is the condition
	// for handing it a failure instead of rendering one here.
	if err := ValidateAuthReqRedirectURI(cr.Client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return nil, err
	}
	redirect, err := s.authorizeWithValidRedirectURI(ctx, cr)
	if err != nil {
		// A StatusError names the status its author wants answered, which only
		// rendering here can honour. See [NewStatusError].
		var statusError StatusError
		if errors.As(err, &statusError) {
			return nil, err
		}
		// TryErrorRedirect returns the error unredirected if it is marked
		// redirect-disabled, which renders it here.
		return TryErrorRedirect(ctx, authReq, err, s.encoder, nil)
	}
	return redirect, nil
}

// authorizeWithValidRedirectURI validates the rest of the request and
// authorizes it, split out so its failures share one error path.
func (s *webServer) authorizeWithValidRedirectURI(ctx context.Context, cr *ClientRequest[oidc.AuthRequest]) (_ *Redirect, err error) {
	authReq := cr.Data
	authReq.MaxAge, err = ValidateAuthReqPrompt(authReq.Prompt, authReq.MaxAge)
	if err != nil {
		return nil, err
	}
	authReq.Scopes, err = ValidateAuthReqScopes(cr.Client, authReq.Scopes)
	if err != nil {
		return nil, err
	}
	if err := ValidateAuthReqResponseType(cr.Client, authReq.ResponseType); err != nil {
		return nil, err
	}
	if err := ValidateAuthReqCodeChallengeMethod(authReq.CodeChallenge, authReq.CodeChallengeMethod); err != nil {
		return nil, err
	}
	return s.server.Authorize(ctx, cr)
}

func (s *webServer) deviceAuthorizationHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.DeviceAuthorizationRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp, err := s.server.DeviceAuthorization(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) tokensHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}

	switch grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType {
	case oidc.GrantTypeCode:
		s.withClient(s.codeExchangeHandler)(w, r)
	case oidc.GrantTypeRefreshToken:
		s.withClient(s.refreshTokenHandler)(w, r)
	case oidc.GrantTypeClientCredentials:
		s.withClient(s.clientCredentialsHandler)(w, r)
	case oidc.GrantTypeBearer:
		s.jwtProfileHandler(w, r)
	case oidc.GrantTypeTokenExchange:
		s.withClient(s.tokenExchangeHandler)(w, r)
	case oidc.GrantTypeDeviceCode:
		s.withClient(s.deviceTokenHandler)(w, r)
	case "":
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("grant_type missing"), nil)
	default:
		WriteError(w, r, unimplementedGrantError(grantType), nil)
	}
}

func (s *webServer) jwtProfileHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.JWTProfileGrantRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if request.Assertion == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("assertion missing"), nil)
		return
	}
	resp, err := s.server.JWTProfile(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) codeExchangeHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.AccessTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if request.Code == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("code missing"), nil)
		return
	}
	if request.RedirectURI == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("redirect_uri missing"), nil)
		return
	}
	resp, err := s.server.CodeExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) refreshTokenHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.RefreshTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if request.RefreshToken == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("refresh_token missing"), nil)
		return
	}
	resp, err := s.server.RefreshToken(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) tokenExchangeHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.TokenExchangeRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if request.SubjectToken == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("subject_token missing"), nil)
		return
	}
	if request.SubjectTokenType == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("subject_token_type missing"), nil)
		return
	}
	if !request.SubjectTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("subject_token_type is not supported"), nil)
		return
	}
	if request.RequestedTokenType != "" && !request.RequestedTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("requested_token_type is not supported"), nil)
		return
	}
	if request.ActorTokenType != "" && !request.ActorTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported"), nil)
		return
	}
	resp, err := s.server.TokenExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) clientCredentialsHandler(w http.ResponseWriter, r *http.Request, client Client) {
	if client.AuthMethod() == oidc.AuthMethodNone {
		WriteError(w, r, oidc.ErrInvalidClient().WithDescription("client must be authenticated"), nil)
		return
	}

	request, err := decodeRequest[oidc.ClientCredentialsRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp, err := s.server.ClientCredentialsExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) deviceTokenHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.DeviceAccessTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if request.DeviceCode == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("device_code missing"), nil)
		return
	}
	resp, err := s.server.DeviceToken(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) introspectionHandler(w http.ResponseWriter, r *http.Request) {
	cc, err := s.parseClientCredentials(r)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if cc.ClientSecret == "" && cc.ClientAssertion == "" {
		WriteError(w, r, oidc.ErrInvalidClient().WithDescription("client must be authenticated"), nil)
		return
	}
	request, err := decodeRequest[oidc.IntrospectionRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if request.Token == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("token missing"), nil)
		return
	}
	resp, err := s.server.Introspect(r.Context(), newRequest(r, &IntrospectionRequest{cc, request}))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) userInfoHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.UserInfoRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if token, err := getAccessToken(r); err == nil {
		request.AccessToken = token
	}
	if request.AccessToken == "" {
		err = NewStatusError(
			oidc.ErrInvalidRequest().WithDescription("access token missing"),
			http.StatusUnauthorized,
		)
		WriteError(w, r, err, nil)
		return
	}
	resp, err := s.server.UserInfo(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) revocationHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.RevocationRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	if request.Token == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("token missing"), nil)
		return
	}
	resp, err := s.server.Revocation(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) endSessionHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.EndSessionRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp, err := s.server.EndSession(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w, r)
}

func simpleHandler(s *webServer, method func(context.Context, *Request[struct{}]) (*Response, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serveSimple(w, r, &struct{}{}, method)
	}
}

// serveSimple parses the form, calls method with data as the request's
// Data and writes the response, or the error.
func serveSimple[T any](w http.ResponseWriter, r *http.Request, data *T, method func(context.Context, *Request[T]) (*Response, error)) {
	if err := r.ParseForm(); err != nil {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), nil)
		return
	}
	resp, err := method(r.Context(), newRequest(r, data))
	if err != nil {
		WriteError(w, r, err, nil)
		return
	}
	resp.writeOut(w)
}

func decodeRequest[R any](decoder httphelper.Decoder, r *http.Request, postOnly bool) (*R, error) {
	dst := new(R)
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	form := r.Form
	if postOnly {
		form = r.PostForm
	}
	if err := decoder.Decode(dst, form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	return dst, nil
}

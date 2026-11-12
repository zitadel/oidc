package op

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/muhlemmer/gu"
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
		// router, so its middleware sees the tenant.
		inner = ws.tenantRouter()
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
// and "/" is the same as "". The prefix is a static path: it must not
// contain the chi pattern characters '{', '}' or '*', and the option
// panics if it does.
//
// A [RegisterServer] handler with this option serves each route of its
// router twice: as "{prefix}/{tenant}{route}" and, for the empty tenant,
// as "{prefix}{route}". With the default endpoints, "/oauth/p1/authorize"
// is the authorization endpoint of tenant "p1" and "/oauth/authorize"
// that of the empty tenant. The routes include those added with
// [WithSetRouter]; the chi URL parameter name "tenant" is taken. The
// empty tenant is for the implementation to interpret: as an issuer of
// its own at https://op.example.com/oauth, or refused. Any other path
// under the prefix reaches the router as it would under a chi Mount at
// "{prefix}/{tenant}": its first segment is the tenant, and the router's
// NotFound handler, mounted routers and middleware handle the rest.
// "{prefix}" and "{prefix}/" are the root of the empty tenant. A path
// outside the prefix, an empty tenant segment, or a tenant of "." or
// ".." gets a JSON 404 that carries the CORS headers. Without this
// option, RegisterServer does no tenant handling and serves its routes
// at its root, as before.
//
// chi tries a static segment before the tenant parameter, so a known
// route wins: tenant T loses its route R only when "/T"+R is itself a
// route. With the endpoints "/a" and "/b/a", "/oauth/b/a" is the empty
// tenant's "/b/a", so tenant "b" has no "/a". The default endpoints
// shadow no tenant route. Opaque tenant IDs, such as random IDs, avoid
// shadowing altogether.
//
// The tenant is set on the context before the router's middleware runs,
// so an [IssuerInterceptor] added with [WithHTTPMiddleware] sees it. That
// middleware runs after the routing above. Middleware that rewrites the
// path, such as chi's
// middleware.StripSlashes, must therefore wrap the handler from outside
// or run on the parent router. The request URL is left as is: the router
// receives the rest of the path as the chi route path, and the chi
// route pattern reads as under a chi Mount, such as
// "/oauth/{tenant}/authorize".
//
// For a [RegisterMetadataServer] handler with this option, with any
// prefix including "", the issuer path must be exactly "{prefix}", for
// the empty tenant, or "{prefix}/{tenant}"; any other issuer path, such as
// a multi-segment one, is a 404 and the [MetadataServer] is not called.
// Without the option, every valid issuer path is passed to the server as
// [MetadataRequest.IssuerPath] and no tenant is set.
//
// Both handlers take the same prefix when the OP handler receives the
// full request path, as on a [http.ServeMux] with mux.Handle("/oauth/", h)
// and no [http.StripPrefix]:
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
// On chi, use r.Mount("/oauth", h). chi strips the mount prefix before
// the handler runs, so the OP handler takes [WithTenantPrefix] with "".
// r.Handle("/oauth/*", h) with the prefix "/oauth" routes too, but as
// for any router nested with Handle, chi's route pattern then repeats
// the prefix, as in "/oauth/oauth/{tenant}/authorize".
//
// chi routes on the raw path when the URL has one. The tenant is
// percent-decoded once from the segment it matched, and a tenant with an
// encoded slash is a 404, as it is for the metadata handler.
//
// EXPERIMENTAL: may change until v4
func WithTenantPrefix(prefix string) ServerOption {
	if strings.ContainsAny(prefix, "{}*") {
		panic(fmt.Sprintf("op: tenant prefix %q must not contain '{', '}' or '*'", prefix))
	}
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

// tenantParam is the chi URL parameter of the tenant segment
// in the routes of [webServer.tenantRouter].
const tenantParam = "tenant"

// tenantRouter implements [WithTenantPrefix] for a [RegisterServer]
// handler. It returns a router that registers every top-level route
// pattern of the handler's own router twice, as "{prefix}/{tenant}{route}" and as
// "{prefix}{route}" for the empty tenant. chi tries a static segment
// before a parameter and falls back to the parameter when the static
// branch has no match, which makes a known route win. Any other path
// under the prefix is forwarded as a chi Mount at "{prefix}/{tenant}"
// would forward it, and "{prefix}" itself as the root of the empty
// tenant, so the router's NotFound handler, mounted routers and
// middleware see it. All routes accept every method, so the handler's
// router answers a wrong method with its 405. A path outside the prefix
// is a 404.
func (s *webServer) tenantRouter() http.Handler {
	outer := chi.NewRouter()
	outer.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeNotFound(w, r, "path is not under the tenant prefix")
	})
	withTenant, emptyTenant := s.forwardTenant(true), s.forwardTenant(false)
	tenantPath := s.tenantPrefix + "/{" + tenantParam + "}"
	outer.Handle(tenantPath, withTenant)
	outer.Handle(tenantPath+"/*", withTenant)
	if s.tenantPrefix != "" {
		outer.Handle(s.tenantPrefix, emptyTenant)
	}
	outer.Handle(s.tenantPrefix+"/", emptyTenant)

	// The top-level patterns, not chi.Walk: a mounted router stays one
	// "/ui/*" route, so its own NotFound handler answers its unknown paths.
	// Routes does not list the "/ui" stub of a Mount, so it is added here.
	for _, route := range s.router.Routes() {
		patterns := []string{route.Pattern}
		if mount, ok := strings.CutSuffix(route.Pattern, "/*"); ok && mount != "" {
			patterns = append(patterns, mount)
		}
		for _, pattern := range patterns {
			outer.Handle(tenantPath+pattern, withTenant)
			outer.Handle(s.tenantPrefix+pattern, emptyTenant)
		}
	}
	return outer
}

// forwardTenant returns the handler of a [webServer.tenantRouter] route,
// which carries the tenant parameter when withTenant is set. It sets the
// tenant on the context and passes the request to the handler's router
// with the chi route path set to the rest of the path after the prefix
// and the tenant, as a chi Mount does. It also replaces the route's
// pattern with the pattern of such a Mount, so that the route pattern
// the handler's router builds, such as "/oauth/{tenant}/authorize", does
// not repeat the route.
func (s *webServer) forwardTenant(withTenant bool) http.HandlerFunc {
	mountPattern := s.tenantPrefix + "/*"
	if withTenant {
		mountPattern = s.tenantPrefix + "/{" + tenantParam + "}/*"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// The path the tenant router matched; the prefix and the raw
		// tenant are at its start, in the same encoding.
		src, escaped := routeSource(r)
		rctx := chi.RouteContext(r.Context())
		n := len(s.tenantPrefix)
		tenant := ""
		if withTenant {
			raw := rctx.URLParam(tenantParam)
			n += 1 + len(raw)
			var err error
			tenant, err = decodeRouteSource(raw, escaped)
			if err != nil || tenant == "" || isDotSegment(tenant) || strings.Contains(tenant, "/") {
				writeNotFound(w, r, "invalid tenant")
				return
			}
		}
		rctx.RoutePath = cmp.Or(src[n:], "/")
		rctx.RoutePatterns[len(rctx.RoutePatterns)-1] = mountPattern
		s.router.ServeHTTP(w, r.WithContext(ContextWithTenant(r.Context(), tenant)))
	}
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
	// tenantSet whether the option was given. RegisterServer and a
	// MetadataHandler handle tenants only when it was.
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
	setNoCacheHeaders(w)
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

// writeTokenResponse writes resp like [Response.writeOut], but sets the
// cache headers required on token responses after merging resp.Header,
// so a custom header can't make the tokens cacheable.
func writeTokenResponse(w http.ResponseWriter, resp *Response) {
	gu.MapMerge(resp.Header, w.Header())
	setNoCacheHeaders(w)
	httphelper.MarshalJSON(w, resp.Data)
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
	writeTokenResponse(w, resp)
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
	writeTokenResponse(w, resp)
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
	writeTokenResponse(w, resp)
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
	writeTokenResponse(w, resp)
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
	writeTokenResponse(w, resp)
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
	writeTokenResponse(w, resp)
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

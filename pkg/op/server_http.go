package op

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
	"github.com/zitadel/logging"
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

	ws := &webServer{
		router:    chi.NewRouter(),
		server:    server,
		endpoints: endpoints,
		decoder:   decoder,
		corsOpts:  &defaultCORSOptions,
		logger:    slog.Default(),
	}

	for _, option := range options {
		option(ws)
	}

	ws.createRouter()
	ws.handler = ws.router
	if ws.corsOpts != nil {
		ws.handler = cors.New(*ws.corsOpts).Handler(ws.router)
	}
	return ws
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

// WithServerCORSOptions sets the CORS policy for the Server's router.
func WithServerCORSOptions(opts *cors.Options) ServerOption {
	return func(s *webServer) {
		s.corsOpts = opts
	}
}

// WithFallbackLogger overrides the fallback logger, which
// is used when no logger was found in the context.
// Defaults to [slog.Default].
func WithFallbackLogger(logger *slog.Logger) ServerOption {
	return func(s *webServer) {
		s.logger = logger
	}
}

type webServer struct {
	server    Server
	router    *chi.Mux
	handler   http.Handler
	endpoints Endpoints
	decoder   httphelper.Decoder
	corsOpts  *cors.Options
	logger    *slog.Logger
}

func (s *webServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *webServer) getLogger(ctx context.Context) *slog.Logger {
	if logger, ok := logging.FromContext(ctx); ok {
		return logger
	}
	return s.logger
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
			ctx, span := tracer.Start(r.Context(), e.Relative())
			r = r.WithContext(ctx)
			hf(w, r)
			defer span.End()
		}
		s.router.HandleFunc(e.Relative(), traceHandler)
		s.logger.Info("registered route", "endpoint", e.Relative())
	}
}

type clientHandler func(w http.ResponseWriter, r *http.Request, client Client)

func (s *webServer) withClient(handler clientHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), r.URL.Path)
		defer span.End()
		r = r.WithContext(ctx)

		client, err := s.verifyRequestClient(r)
		if err != nil {
			WriteError(w, r, err, s.getLogger(r.Context()))
			return
		}
		if grantType := oidc.GrantType(r.Form.Get("grant_type")); grantType != "" {
			if !ValidateGrantType(client, grantType) {
				WriteError(w, r, oidc.ErrUnauthorizedClient().WithDescription("grant_type %q not allowed", grantType), s.getLogger(r.Context()))
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
	// Basic auth takes precedence, so if set it overwrites the form data.
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
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
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	redirect, err := s.authorize(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	redirect.writeOut(w, r)
}

func (s *webServer) authorize(ctx context.Context, r *Request[oidc.AuthRequest]) (_ *Redirect, err error) {
	cr, err := s.server.VerifyAuthRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	authReq := cr.Data
	if authReq.RedirectURI == "" {
		return nil, ErrAuthReqMissingRedirectURI
	}
	authReq.MaxAge, err = ValidateAuthReqPrompt(authReq.Prompt, authReq.MaxAge)
	if err != nil {
		return nil, err
	}
	authReq.Scopes, err = ValidateAuthReqScopes(cr.Client, authReq.Scopes)
	if err != nil {
		return nil, err
	}
	if err := ValidateAuthReqRedirectURI(cr.Client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return nil, err
	}
	if err := ValidateAuthReqResponseType(cr.Client, authReq.ResponseType); err != nil {
		return nil, err
	}
	return s.server.Authorize(ctx, cr)
}

func (s *webServer) deviceAuthorizationHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.DeviceAuthorizationRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.DeviceAuthorization(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) tokensHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), s.getLogger(r.Context()))
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
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("grant_type missing"), s.getLogger(r.Context()))
	default:
		WriteError(w, r, unimplementedGrantError(grantType), s.getLogger(r.Context()))
	}
}

func (s *webServer) jwtProfileHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.JWTProfileGrantRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if request.Assertion == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("assertion missing"), s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.JWTProfile(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) codeExchangeHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.AccessTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if request.Code == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("code missing"), s.getLogger(r.Context()))
		return
	}
	if request.RedirectURI == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("redirect_uri missing"), s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.CodeExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) refreshTokenHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.RefreshTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if request.RefreshToken == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("refresh_token missing"), s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.RefreshToken(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) tokenExchangeHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.TokenExchangeRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if request.SubjectToken == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("subject_token missing"), s.getLogger(r.Context()))
		return
	}
	if request.SubjectTokenType == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("subject_token_type missing"), s.getLogger(r.Context()))
		return
	}
	if !request.SubjectTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("subject_token_type is not supported"), s.getLogger(r.Context()))
		return
	}
	if request.RequestedTokenType != "" && !request.RequestedTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("requested_token_type is not supported"), s.getLogger(r.Context()))
		return
	}
	if request.ActorTokenType != "" && !request.ActorTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported"), s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.TokenExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) clientCredentialsHandler(w http.ResponseWriter, r *http.Request, client Client) {
	if client.AuthMethod() == oidc.AuthMethodNone {
		WriteError(w, r, oidc.ErrInvalidClient().WithDescription("client must be authenticated"), s.getLogger(r.Context()))
		return
	}

	request, err := decodeRequest[oidc.ClientCredentialsRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.ClientCredentialsExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) deviceTokenHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.DeviceAccessTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if request.DeviceCode == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("device_code missing"), s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.DeviceToken(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) introspectionHandler(w http.ResponseWriter, r *http.Request) {
	cc, err := s.parseClientCredentials(r)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if cc.ClientSecret == "" && cc.ClientAssertion == "" {
		WriteError(w, r, oidc.ErrInvalidClient().WithDescription("client must be authenticated"), s.getLogger(r.Context()))
		return
	}
	request, err := decodeRequest[oidc.IntrospectionRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if request.Token == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("token missing"), s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.Introspect(r.Context(), newRequest(r, &IntrospectionRequest{cc, request}))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) userInfoHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.UserInfoRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
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
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.UserInfo(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) revocationHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.RevocationRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	if request.Token == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("token missing"), s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.Revocation(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w)
}

func (s *webServer) endSessionHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.EndSessionRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp, err := s.server.EndSession(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.getLogger(r.Context()))
		return
	}
	resp.writeOut(w, r)
}

func simpleHandler(s *webServer, method func(context.Context, *Request[struct{}]) (*Response, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), s.getLogger(r.Context()))
			return
		}
		resp, err := method(r.Context(), newRequest(r, &struct{}{}))
		if err != nil {
			WriteError(w, r, err, s.getLogger(r.Context()))
			return
		}
		resp.writeOut(w)
	}
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

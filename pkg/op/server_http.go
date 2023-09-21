package op

import (
	"context"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/rs/cors"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/schema"
	"golang.org/x/exp/slog"
)

func RegisterServer(server Server, options ...ServerOption) http.Handler {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	ws := &webServer{
		server:    server,
		endpoints: *DefaultEndpoints,
		decoder:   decoder,
		logger:    slog.Default(),
	}

	for _, option := range options {
		option(ws)
	}

	ws.createRouter()
	return ws
}

type ServerOption func(s *webServer)

func WithHTTPMiddleware(m ...func(http.Handler) http.Handler) ServerOption {
	return func(s *webServer) {
		s.middleware = m
	}
}

type webServer struct {
	http.Handler
	server     Server
	middleware []func(http.Handler) http.Handler
	endpoints  Endpoints
	decoder    httphelper.Decoder
	logger     *slog.Logger
}

func (s *webServer) createRouter() {
	router := chi.NewRouter()
	router.Use(cors.New(defaultCORSOptions).Handler)
	router.Use(s.middleware...)
	router.HandleFunc(healthEndpoint, simpleHandler(s, s.server.Health))
	router.HandleFunc(readinessEndpoint, simpleHandler(s, s.server.Ready))
	router.HandleFunc(oidc.DiscoveryEndpoint, simpleHandler(s, s.server.Discovery))
	router.HandleFunc(s.endpoints.Authorization.Relative(), s.authorizeHandler)
	router.HandleFunc(s.endpoints.DeviceAuthorization.Relative(), s.deviceAuthorizationHandler)
	router.HandleFunc(s.endpoints.Token.Relative(), s.tokensHandler)
	router.HandleFunc(s.endpoints.Introspection.Relative(), s.introspectionHandler)
	router.HandleFunc(s.endpoints.Userinfo.Relative(), s.userInfoHandler)
	router.HandleFunc(s.endpoints.Revocation.Relative(), s.revokationHandler)
	router.HandleFunc(s.endpoints.EndSession.Relative(), s.endSessionHandler)
	router.HandleFunc(s.endpoints.JwksURI.Relative(), simpleHandler(s, s.server.Keys))
	s.Handler = router
}

func (s *webServer) verifyRequestClient(r *http.Request) (Client, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	cc := new(ClientCredentials)
	if err := s.decoder.Decode(cc, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	// Basic auth takes precedence, so if set it overwrites the form data.
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		cc.ClientID, cc.ClientSecret = clientID, clientSecret
	}
	if cc.ClientID == "" && cc.ClientAssertion == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("client_id or client_assertion must be provided")
	}
	if cc.ClientAssertion != "" && cc.ClientAssertionType != oidc.ClientAssertionTypeJWTAssertion {
		return nil, oidc.ErrInvalidRequest().WithDescription("invalid client_assertion_type %s", cc.ClientAssertionType)
	}
	return s.server.VerifyClient(r.Context(), &Request[ClientCredentials]{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		Form:   r.Form,
		Data:   cc,
	})
}

func (s *webServer) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.AuthRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	redirect, err := s.authorize(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.logger)
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

func (s *webServer) deviceAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	client, err := s.verifyRequestClient(r)
	if err != nil {
		WriteError(w, r, err, slog.Default())
		return
	}
	request, err := decodeRequest[oidc.DeviceAuthorizationRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp, err := s.server.DeviceAuthorization(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) tokensHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), s.logger)
		return
	}
	grantType := oidc.GrantType(r.Form.Get("grant_type"))
	if grantType == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("grant_type missing"), slog.Default())
		return
	}
	if !grantType.IsSupported() {
		WriteError(w, r, unimplementedGrantError(grantType), s.logger)
		return
	}

	if grantType == oidc.GrantTypeBearer {
		s.jwtProfileHandler(w, r)
		return
	}

	client, err := s.verifyRequestClient(r)
	if err != nil {
		WriteError(w, r, err, slog.Default())
		return
	}
	if !ValidateGrantType(client, grantType) {
		WriteError(w, r, oidc.ErrUnauthorizedClient().WithDescription("grant_type %q not allowed", grantType), s.logger)
		return
	}

	switch grantType {
	case oidc.GrantTypeCode:
		s.codeExchangeHandler(w, r, client)
	case oidc.GrantTypeRefreshToken:
		s.refreshTokenHandler(w, r, client)
	case oidc.GrantTypeTokenExchange:
		s.tokenExchangeHandler(w, r, client)
	case oidc.GrantTypeClientCredentials:
		s.clientCredentialsHandler(w, r, client)
	case oidc.GrantTypeDeviceCode:
		s.deviceTokenHandler(w, r, client)
	default:
		WriteError(w, r, unimplementedGrantError(grantType), s.logger)
	}
}

func (s *webServer) jwtProfileHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.JWTProfileGrantRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	if request.Assertion == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("assertion missing"), s.logger)
		return
	}
	resp, err := s.server.JWTProfile(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) codeExchangeHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.AccessTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	if request.Code == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("code missing"), s.logger)
		return
	}
	if request.RedirectURI == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("redirect_uri missing"), s.logger)
		return
	}
	resp, err := s.server.CodeExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) refreshTokenHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.RefreshTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	if request.RefreshToken == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("refresh_token missing"), s.logger)
		return
	}
	resp, err := s.server.RefreshToken(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) tokenExchangeHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.TokenExchangeRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	if request.SubjectToken == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported"), s.logger)
		return
	}
	if request.SubjectTokenType == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported"), s.logger)
		return
	}
	if request.RequestedTokenType != "" && !request.RequestedTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported"), s.logger)
		return
	}
	if !request.SubjectTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported"), s.logger)
		return
	}
	if request.ActorTokenType != "" && !request.ActorTokenType.IsSupported() {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported"), s.logger)
		return
	}
	resp, err := s.server.TokenExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) clientCredentialsHandler(w http.ResponseWriter, r *http.Request, client Client) {
	if client.AuthMethod() == oidc.AuthMethodNone {
		err := oidc.ErrInvalidClient().WithDescription("client must be authenticated")
		WriteError(w, r, err, s.logger)
		return
	}

	request, err := decodeRequest[oidc.ClientCredentialsRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp, err := s.server.ClientCredentialsExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) deviceTokenHandler(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[oidc.DeviceAccessTokenRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	if request.DeviceCode == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("device_code missing"), s.logger)
		return
	}
	resp, err := s.server.DeviceToken(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) introspectionHandler(w http.ResponseWriter, r *http.Request) {
	client, err := s.verifyRequestClient(r)
	if err != nil {
		WriteError(w, r, err, slog.Default())
		return
	}
	request, err := decodeRequest[oidc.IntrospectionRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	if request.Token == "" {
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("token missing"), s.logger)
		return
	}
	resp, err := s.server.Introspect(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) userInfoHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.UserInfoRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	if token, err := getAccessToken(r); err == nil {
		request.AccessToken = token
	}
	if request.AccessToken == "" {
		err = AsStatusError(
			oidc.ErrInvalidRequest().WithDescription("access token missing"),
			http.StatusUnauthorized,
		)
		WriteError(w, r, err, s.logger)
		return
	}
	resp, err := s.server.UserInfo(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) revokationHandler(w http.ResponseWriter, r *http.Request) {
	client, err := s.verifyRequestClient(r)
	if err != nil {
		WriteError(w, r, err, slog.Default())
		return
	}
	request, err := decodeRequest[oidc.RevocationRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp, err := s.server.Revocation(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) endSessionHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[oidc.EndSessionRequest](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp, err := s.server.EndSession(r.Context(), newRequest(r, request))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w, r)
}

func simpleHandler(s *webServer, method func(context.Context, *Request[struct{}]) (*Response, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err), s.logger)
			return
		}
		resp, err := method(r.Context(), newRequest(r, &struct{}{}))
		if err != nil {
			WriteError(w, r, err, s.logger)
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

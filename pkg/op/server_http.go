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

func RegisterServer(server Server) http.Handler {
	ws := &webServer{
		server:    server,
		endpoints: *DefaultEndpoints,
		decoder:   schema.NewDecoder(),
		logger:    slog.Default(),
	}
	ws.createRouter()
	return ws
}

type webServer struct {
	http.Handler
	server    Server
	endpoints Endpoints
	decoder   httphelper.Decoder
	logger    *slog.Logger
}

func (s *webServer) createRouter(interceptors ...func(http.Handler) http.Handler) {
	router := chi.NewRouter()
	router.Use(cors.New(defaultCORSOptions).Handler)
	router.Use(interceptors...)
	router.HandleFunc(healthEndpoint, simpleHandler(s, s.server.Health))
	router.HandleFunc(readinessEndpoint, simpleHandler(s, s.server.Ready))
	router.HandleFunc(oidc.DiscoveryEndpoint, simpleHandler(s, s.server.Discovery))
	router.HandleFunc(s.endpoints.Authorization.Relative(), redirectHandler(s, s.server.Authorize))
	router.HandleFunc(s.endpoints.Token.Relative(), s.tokensHandler)
	router.HandleFunc(s.endpoints.Introspection.Relative(), clientRequestHandler(s, s.server.Introspect))
	router.HandleFunc(s.endpoints.Userinfo.Relative(), requestHandler(s, s.server.UserInfo))
	router.HandleFunc(s.endpoints.Revocation.Relative(), clientRequestHandler(s, s.server.Revocation))
	router.HandleFunc(s.endpoints.EndSession.Relative(), redirectHandler(s, s.server.EndSession))
	router.HandleFunc(s.endpoints.JwksURI.Relative(), simpleHandler(s, s.server.Keys))
	router.HandleFunc(s.endpoints.DeviceAuthorization.Relative(), clientRequestHandler(s, s.server.DeviceAuthorization))
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

func (s *webServer) tokensHandler(w http.ResponseWriter, r *http.Request) {
	grantType := oidc.GrantType(r.Form.Get("grant_type"))
	if grantType == oidc.GrantTypeBearer {
		callRequestMethod(s, w, r, s.server.JWTProfile)
		return
	}

	client, err := s.verifyRequestClient(r)
	if err != nil {
		WriteError(w, r, err, slog.Default())
		return
	}

	switch grantType {
	case oidc.GrantTypeCode:
		callClientMethod(s, w, r, client, s.server.CodeExchange)
	case oidc.GrantTypeRefreshToken:
		callClientMethod(s, w, r, client, s.server.RefreshToken)
	case oidc.GrantTypeTokenExchange:
		callClientMethod(s, w, r, client, s.server.TokenExchange)
	case oidc.GrantTypeClientCredentials:
		callClientMethod(s, w, r, client, s.server.ClientCredentialsExchange)
	case oidc.GrantTypeDeviceCode:
		callClientMethod(s, w, r, client, s.server.DeviceToken)
	case "":
		WriteError(w, r, oidc.ErrInvalidRequest().WithDescription("grant_type missing"), slog.Default())
	default:
		WriteError(w, r, unimplementedGrantError(grantType), slog.Default())
	}
}

type requestMethod[T any] func(context.Context, *Request[T]) (*Response, error)

func simpleHandler(s *webServer, method requestMethod[struct{}]) http.HandlerFunc {
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

func requestHandler[T any](s *webServer, method requestMethod[T]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		callRequestMethod(s, w, r, method)
	}
}

func callRequestMethod[T any](s *webServer, w http.ResponseWriter, r *http.Request, method requestMethod[T]) {
	request, err := decodeRequest[T](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp, err := method(r.Context(), newRequest[T](r, request))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

type redirectMethod[T any] func(context.Context, *Request[T]) (*Redirect, error)

func redirectHandler[T any](s *webServer, method redirectMethod[T]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeRequest[T](s.decoder, r, false)
		if err != nil {
			WriteError(w, r, err, s.logger)
			return
		}
		redirect, err := method(r.Context(), newRequest(r, req))
		if err != nil {
			WriteError(w, r, err, s.logger)
			return
		}
		redirect.writeOut(w, r)
	}
}

type clientMethod[T any] func(context.Context, *ClientRequest[T]) (*Response, error)

func clientRequestHandler[T any](s *webServer, method clientMethod[T]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := s.verifyRequestClient(r)
		if err != nil {
			WriteError(w, r, err, slog.Default())
			return
		}
		callClientMethod(s, w, r, client, method)
	}
}

func callClientMethod[T any](s *webServer, w http.ResponseWriter, r *http.Request, client Client, method clientMethod[T]) {
	request, err := decodeRequest[T](s.decoder, r, false)
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp, err := method(r.Context(), newClientRequest[T](r, request, client))
	if err != nil {
		WriteError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func decodeRequest[R any](decoder httphelper.Decoder, r *http.Request, postOnly bool) (*R, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	form := r.Form
	if postOnly {
		form = r.PostForm
	}
	request := new(R)
	if err := decoder.Decode(request, form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	return request, nil
}

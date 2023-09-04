package op

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/rs/cors"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/exp/slog"
)

type webServer struct {
	http.Handler
	decoder httphelper.Decoder
	server  Server
	logger  *slog.Logger
}

func (s *webServer) createRouter(endpoints *Endpoints, interceptors ...func(http.Handler) http.Handler) chi.Router {
	router := chi.NewRouter()
	router.Use(cors.New(defaultCORSOptions).Handler)
	router.Use(interceptors...)
	router.HandleFunc(healthEndpoint, healthHandler)
	//router.HandleFunc(readinessEndpoint, readyHandler(o.Probes()))
	//router.HandleFunc(oidc.DiscoveryEndpoint, discoveryHandler(o, o.Storage()))
	//router.HandleFunc(o.AuthorizationEndpoint().Relative(), authorizeHandler(o))
	//router.HandleFunc(authCallbackPath(o), authorizeCallbackHandler(o))
	router.HandleFunc(endpoints.Token.Relative(), s.handleToken)
	//router.HandleFunc(o.IntrospectionEndpoint().Relative(), introspectionHandler(o))
	//router.HandleFunc(o.UserinfoEndpoint().Relative(), userinfoHandler(o))
	//router.HandleFunc(o.RevocationEndpoint().Relative(), revocationHandler(o))
	//router.HandleFunc(o.EndSessionEndpoint().Relative(), endSessionHandler(o))
	//router.HandleFunc(o.KeysEndpoint().Relative(), keysHandler(o.Storage()))
	//router.HandleFunc(o.DeviceAuthorizationEndpoint().Relative(), DeviceAuthorizationHandler(o))
	return router
}

func (s *webServer) verifyRequestClient(r *http.Request) (Client, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	clientCredentials := new(ClientCredentials)
	if err := s.decoder.Decode(clientCredentials, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	// Basic auth takes precedence, so if set it overwrites the form data.
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		clientCredentials.ClientID, clientCredentials.ClientSecret = clientID, clientSecret
	}

	return s.server.VerifyClient(r.Context(), &Request[ClientCredentials]{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		Form:   r.Form,
		Data:   clientCredentials,
	})
}

func (s *webServer) handleToken(w http.ResponseWriter, r *http.Request) {
	client, err := s.verifyRequestClient(r)
	if err != nil {
		RequestError(w, r, err, slog.Default())
		return
	}

	grantType := oidc.GrantType(r.Form.Get("grant_type"))
	var handle func(w http.ResponseWriter, r *http.Request, client Client)
	switch grantType {
	case oidc.GrantTypeCode:
		handle = s.handleCodeExchange
	case oidc.GrantTypeRefreshToken:
		handle = s.handleRefreshToken
	case "":
		RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("grant_type missing"), slog.Default())
		return
	default:
		RequestError(w, r, oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", grantType), slog.Default())
		return
	}

	handle(w, r, client)
}

func (s *webServer) handleCodeExchange(w http.ResponseWriter, r *http.Request, client Client) {
	request, err := decodeRequest[*oidc.AccessTokenRequest](s.decoder, r.Form)
	if err != nil {
		RequestError(w, r, err, s.logger)
		return
	}
	resp, err := s.server.CodeExchange(r.Context(), newClientRequest(r, request, client))
	if err != nil {
		RequestError(w, r, err, s.logger)
		return
	}
	resp.writeOut(w)
}

func (s *webServer) handleRefreshToken(w http.ResponseWriter, r *http.Request, client Client) {

}

func decodeRequest[R any](decoder httphelper.Decoder, form map[string][]string) (request R, err error) {
	if err := decoder.Decode(&request, form); err != nil {
		return request, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	return request, nil
}

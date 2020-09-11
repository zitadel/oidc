package op

import (
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"github.com/caos/oidc/pkg/oidc"
)

const (
	healthzEndpoint   = "/healthz"
	readinessEndpoint = "/ready"
)

type OpenIDProvider interface {
	Configuration
	Authorizer
	SessionEnder
	Signer() Signer
	Probes() []ProbesFn
	HttpHandler() http.Handler
}

type HttpInterceptor func(http.Handler) http.Handler

var allowAllOrigins = func(_ string) bool {
	return true
}

func CreateRouter(o OpenIDProvider, interceptors ...HttpInterceptor) *mux.Router {
	intercept := buildInterceptor(interceptors...)
	router := mux.NewRouter()
	router.Use(handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedHeaders([]string{"authorization", "content-type"}),
		handlers.AllowedOriginValidator(allowAllOrigins),
	))
	router.HandleFunc(healthzEndpoint, Healthz)
	router.HandleFunc(readinessEndpoint, Ready(o.Probes()))
	router.HandleFunc(oidc.DiscoveryEndpoint, DiscoveryHandler(o, o.Signer()))
	router.Handle(o.AuthorizationEndpoint().Relative(), intercept(authorizeHandler(o)))
	router.Handle(o.AuthorizationEndpoint().Relative()+"/{id}", intercept(authorizeCallbackHandler(o)))
	router.Handle(o.TokenEndpoint().Relative(), intercept(tokenHandler(o)))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), userinfoHandler(o))
	router.Handle(o.EndSessionEndpoint().Relative(), intercept(endSessionHandler(o)))
	router.HandleFunc(o.KeysEndpoint().Relative(), keysHandler(o))
	return router
}

func buildInterceptor(interceptors ...HttpInterceptor) func(http.HandlerFunc) http.Handler {
	return func(handlerFunc http.HandlerFunc) http.Handler {
		handler := handlerFuncToHandler(handlerFunc)
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return handler
	}
}

func handlerFuncToHandler(handlerFunc http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerFunc(w, r)
	})
}

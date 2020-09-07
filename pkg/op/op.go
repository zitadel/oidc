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
	HandleReady(w http.ResponseWriter, r *http.Request)
	HandleDiscovery(w http.ResponseWriter, r *http.Request)
	HandleAuthorize(w http.ResponseWriter, r *http.Request)
	HandleAuthorizeCallback(w http.ResponseWriter, r *http.Request)
	HandleExchange(w http.ResponseWriter, r *http.Request)
	HandleUserinfo(w http.ResponseWriter, r *http.Request)
	HandleEndSession(w http.ResponseWriter, r *http.Request)
	HandleKeys(w http.ResponseWriter, r *http.Request)
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
	router.HandleFunc(readinessEndpoint, o.HandleReady)
	router.HandleFunc(oidc.DiscoveryEndpoint, o.HandleDiscovery)
	router.Handle(o.AuthorizationEndpoint().Relative(), intercept(o.HandleAuthorize))
	router.Handle(o.AuthorizationEndpoint().Relative()+"/{id}", intercept(o.HandleAuthorizeCallback))
	router.Handle(o.TokenEndpoint().Relative(), intercept(o.HandleExchange))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), o.HandleUserinfo)
	router.Handle(o.EndSessionEndpoint().Relative(), intercept(o.HandleEndSession))
	router.HandleFunc(o.KeysEndpoint().Relative(), o.HandleKeys)
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

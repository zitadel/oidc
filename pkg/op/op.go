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

type HttpInterceptor func(http.HandlerFunc) http.HandlerFunc

var DefaultInterceptor = func(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(w, r)
	})
}

func CreateRouter(o OpenIDProvider, h HttpInterceptor) *mux.Router {
	if h == nil {
		h = DefaultInterceptor
	}
	router := mux.NewRouter()
	router.Use(handlers.CORS())
	router.HandleFunc(healthzEndpoint, Healthz)
	router.HandleFunc(readinessEndpoint, o.HandleReady)
	router.HandleFunc(oidc.DiscoveryEndpoint, o.HandleDiscovery)
	router.HandleFunc(o.AuthorizationEndpoint().Relative(), h(o.HandleAuthorize))
	router.HandleFunc(o.AuthorizationEndpoint().Relative()+"/{id}", h(o.HandleAuthorizeCallback))
	router.HandleFunc(o.TokenEndpoint().Relative(), h(o.HandleExchange))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), o.HandleUserinfo)
	router.HandleFunc(o.EndSessionEndpoint().Relative(), h(o.HandleEndSession))
	router.HandleFunc(o.KeysEndpoint().Relative(), o.HandleKeys)
	return router
}

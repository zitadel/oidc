package op

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/caos/oidc/pkg/oidc"
)

type OpenIDProvider interface {
	Configuration
	HandleDiscovery(w http.ResponseWriter, r *http.Request)
	HandleAuthorize(w http.ResponseWriter, r *http.Request)
	HandleAuthorizeCallback(w http.ResponseWriter, r *http.Request)
	HandleExchange(w http.ResponseWriter, r *http.Request)
	HandleUserinfo(w http.ResponseWriter, r *http.Request)
	HandleKeys(w http.ResponseWriter, r *http.Request)
	HttpHandler() *http.Server
}

type HttpInterceptor func(http.HandlerFunc) http.HandlerFunc

var (
	DefaultInterceptor = func(h http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h(w, r)
		})
	}
)

func CreateRouter(o OpenIDProvider, h HttpInterceptor) *mux.Router {
	if h == nil {
		h = DefaultInterceptor
	}
	router := mux.NewRouter()
	router.HandleFunc(oidc.DiscoveryEndpoint, o.HandleDiscovery)
	router.HandleFunc(o.AuthorizationEndpoint().Relative(), h(o.HandleAuthorize))
	router.HandleFunc(o.AuthorizationEndpoint().Relative()+"/{id}", h(o.HandleAuthorizeCallback))
	router.HandleFunc(o.TokenEndpoint().Relative(), h(o.HandleExchange))
	router.HandleFunc(o.UserinfoEndpoint().Relative(), o.HandleUserinfo)
	router.HandleFunc(o.KeysEndpoint().Relative(), o.HandleKeys)
	return router
}

func Start(ctx context.Context, o OpenIDProvider) {
	go func() {
		<-ctx.Done()
		err := o.HttpHandler().Shutdown(ctx)
		if err != nil {
			logrus.Error("graceful shutdown of oidc server failed")
		}
	}()

	go func() {
		err := o.HttpHandler().ListenAndServe()
		if err != nil {
			logrus.Panicf("oidc server serve failed: %v", err)
		}
	}()
	logrus.Infof("oidc server is listening on %s", o.Port())
}

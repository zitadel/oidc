package server

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/utils/logging"
)

type OpenIDProvider interface {
	Configuration
	// Storage() Storage
	HandleDiscovery(w http.ResponseWriter, r *http.Request)
	HandleAuthorize(w http.ResponseWriter, r *http.Request)
	HandleExchange(w http.ResponseWriter, r *http.Request)
	HandleUserinfo(w http.ResponseWriter, r *http.Request)
	HttpHandler() *http.Server
}

func CreateRouter(o OpenIDProvider) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc(oidc.DiscoveryEndpoint, o.HandleDiscovery)
	router.HandleFunc(o.AuthorizationEndpoint().Relative(), o.HandleAuthorize)
	router.HandleFunc(o.TokenEndpoint().Relative(), o.HandleExchange)
	router.HandleFunc(o.UserinfoEndpoint().Relative(), o.HandleUserinfo)
	return router
}

func Start(ctx context.Context, o OpenIDProvider) {
	go func() {
		<-ctx.Done()
		err := o.HttpHandler().Shutdown(ctx)
		logging.Log("SERVE-REqwpM").OnError(err).Error("graceful shutdown of oidc server failed")
	}()

	go func() {
		err := o.HttpHandler().ListenAndServe()
		logging.Log("SERVE-4YNIwG").OnError(err).Panic("oidc server serve failed")
	}()
	logging.LogWithFields("SERVE-koAFMs", "port", o.Port()).Info("oidc server is listening")
}

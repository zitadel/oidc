package server

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/utils/logging"
)

type Handler interface {
	Configuration
	// Storage() Storage
	HandleDiscovery(w http.ResponseWriter, r *http.Request)
	HandleAuthorize(w http.ResponseWriter, r *http.Request)
	HandleExchange(w http.ResponseWriter, r *http.Request)
	HandleUserinfo(w http.ResponseWriter, r *http.Request)
	HttpHandler() *http.Server
}

func CreateRouter(h Handler) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc(oidc.DiscoveryEndpoint, h.HandleDiscovery)
	router.HandleFunc(h.AuthorizationEndpoint(), h.HandleAuthorize)
	router.HandleFunc(h.TokenEndpoint(), h.HandleExchange)
	router.HandleFunc(h.UserinfoEndpoint(), h.HandleUserinfo)
	return router
}

func Start(ctx context.Context, h Handler) {
	go func() {
		<-ctx.Done()
		err := h.HttpHandler().Shutdown(ctx)
		logging.Log("SERVE-REqwpM").OnError(err).Error("graceful shutdown of oidc server failed")
	}()

	go func() {
		err := h.HttpHandler().ListenAndServe()
		logging.Log("SERVE-4YNIwG").OnError(err).Panic("oidc server serve failed")
	}()
	logging.LogWithFields("SERVE-koAFMs", "port", h.Port()).Info("oidc server is listening")
}

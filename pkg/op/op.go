package op

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/utils/logging"
)

type OpenIDProvider interface {
	Configuration
	// Storage() Storage
	HandleDiscovery(w http.ResponseWriter, r *http.Request)
	HandleAuthorize(w http.ResponseWriter, r *http.Request)
	HandleAuthorizeCallback(w http.ResponseWriter, r *http.Request)
	HandleExchange(w http.ResponseWriter, r *http.Request)
	HandleUserinfo(w http.ResponseWriter, r *http.Request)
	// Storage() Storage
	HttpHandler() *http.Server
}

func ValidateIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("missing issuer")
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return errors.New("invalid url for issuer")
	}
	if u.Host == "" {
		return errors.New("host for issuer missing")
	}
	if u.Scheme != "https" {
		if !(u.Scheme == "http" && (u.Host == "localhost" || u.Host == "127.0.0.1" || u.Host == "::1" || strings.HasPrefix(u.Host, "localhost:"))) { //TODO: ?
			return errors.New("scheme for issuer must be `https`")
		}
	}
	if u.Fragment != "" || len(u.Query()) > 0 {
		return errors.New("no fragments or query allowed for issuer")
	}
	return nil
}

func CreateRouter(o OpenIDProvider) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc(oidc.DiscoveryEndpoint, o.HandleDiscovery)
	router.HandleFunc(o.AuthorizationEndpoint().Relative(), o.HandleAuthorize)
	router.HandleFunc(o.AuthorizationEndpoint().Relative()+"/{id}", o.HandleAuthorizeCallback)
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

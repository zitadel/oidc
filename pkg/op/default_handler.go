package server

import (
	"net/http"

	"github.com/caos/oidc/pkg/utils"

	"github.com/caos/oidc/pkg/oidc"
)

type DefaultHandler struct {
	config          *Config
	discoveryConfig *oidc.DiscoveryConfiguration
	storage         Storage
	http            *http.Server
}

type Config struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	Port                  string
}

func (c *Config) OIDC() *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{}
}

func NewDefaultHandler(config *Config, storage Storage) Handler {
	h := &DefaultHandler{
		config:          config,
		discoveryConfig: config.OIDC(),
		storage:         storage,
	}
	router := CreateRouter(h)
	h.http = &http.Server{
		Addr:    config.Port,
		Handler: router,
	}

	return h
}

func (h *DefaultHandler) Issuer() string {
	return h.config.Issuer
}

func (h *DefaultHandler) AuthorizationEndpoint() string {
	return h.config.AuthorizationEndpoint

}

func (h *DefaultHandler) TokenEndpoint() string {
	return h.config.TokenEndpoint
}

func (h *DefaultHandler) UserinfoEndpoint() string {
	return h.config.UserinfoEndpoint
}

func (h *DefaultHandler) Port() string {
	return h.config.Port
}

func (h *DefaultHandler) HttpHandler() *http.Server {
	return h.http
}

func (h *DefaultHandler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	utils.MarshalJSON(w, h.discoveryConfig)
}

func (h *DefaultHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	authRequest, err := ParseAuthRequest(w, r)
	if err != nil {
		//TODO: return err
	}
	err = ValidateAuthRequest(authRequest)
	if err != nil {
		//TODO: return err
	}
	if NeedsExistingSession(authRequest) {
		// session, err := h.storage.CheckSession(authRequest)
		// if err != nil {
		// 	//TODO: return err
		// }
	}
	err = h.storage.CreateAuthRequest(authRequest)
	if err != nil {
		//TODO: return err
	}
	//TODO: redirect?
}

func (h *DefaultHandler) HandleExchange(w http.ResponseWriter, r *http.Request) {
}

func (h *DefaultHandler) HandleUserinfo(w http.ResponseWriter, r *http.Request) {

}

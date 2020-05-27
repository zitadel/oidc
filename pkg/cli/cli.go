package cli

import (
	"context"
	"fmt"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/rp"
	"github.com/caos/oidc/pkg/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"log"
	"net/http"
	"strings"
	"time"
)

func CodeFlow(rpc *rp.Config, key []byte, callbackPath string, port string) *oidc.Tokens {
	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	provider, err := rp.NewDefaultRP(rpc, rp.WithCookieHandler(cookieHandler)) //rp.WithPKCE(cookieHandler)) //,
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	return codeFlow(provider, callbackPath, port)
}

func TokenForClient(rpc *rp.Config, key []byte, token *oidc.Tokens) *http.Client {
	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	provider, err := rp.NewDefaultRP(rpc, rp.WithCookieHandler(cookieHandler)) //rp.WithPKCE(cookieHandler)) //,
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	return provider.Client(context.Background(), token.Token)
}

func CodeFlowForClient(rpc *rp.Config, key []byte, callbackPath string, port string) *http.Client {
	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	provider, err := rp.NewDefaultRP(rpc, rp.WithCookieHandler(cookieHandler)) //rp.WithPKCE(cookieHandler)) //,
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}
	token := codeFlow(provider, callbackPath, port)

	return provider.Client(context.Background(), token.Token)
}

func codeFlow(provider rp.DelegationTokenExchangeRP, callbackPath string, port string) *oidc.Tokens {
	loginPath := "/login"
	portStr := port
	if !strings.HasPrefix(port, ":") {
		portStr = strings.Join([]string{":", portStr}, "")
	}

	getToken, setToken := getAndSetTokens()

	state := uuid.New().String()
	http.Handle(loginPath, provider.AuthURLHandler(state))

	marshal := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string) {
		setToken(w, tokens)
	}
	http.Handle(callbackPath, provider.CodeExchangeHandler(marshal))

	// start  http-server
	stopHttpServer := startHttpServer(portStr)

	// open browser in different window
	utils.OpenBrowser(strings.Join([]string{"http://localhost", portStr, loginPath}, ""))

	// wait until user is logged into browser
	ret := getToken()

	// stop http-server as no callback is needed anymore
	stopHttpServer()

	// return tokens
	return ret
}

func startHttpServer(port string) func() {
	srv := &http.Server{Addr: port}
	go func() {

		// always returns error. ErrServerClosed on graceful close
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// unexpected error. port in use?
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalf("Shutdown(): %v", err)
		}
	}
}

func getAndSetTokens() (func() *oidc.Tokens, func(w http.ResponseWriter, tokens *oidc.Tokens)) {
	marshalChan := make(chan *oidc.Tokens)

	getToken := func() *oidc.Tokens {
		return <-marshalChan
	}
	setToken := func(w http.ResponseWriter, tokens *oidc.Tokens) {
		marshalChan <- tokens

		msg := "<p><strong>Success!</strong></p>"
		msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
		fmt.Fprintf(w, msg)
	}

	return getToken, setToken
}

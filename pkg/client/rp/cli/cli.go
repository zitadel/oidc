package cli

import (
	"context"
	"net/http"

	"github.com/caos/oidc/pkg/client/rp"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

const (
	loginPath = "/login"
)

func CodeFlow(ctx context.Context, relyingParty rp.RelyingParty, callbackPath, port string, stateProvider func() string) *oidc.Tokens {
	codeflowCtx, codeflowCancel := context.WithCancel(ctx)
	defer codeflowCancel()

	tokenChan := make(chan *oidc.Tokens, 1)

	callback := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
		tokenChan <- tokens
		msg := "<p><strong>Success!</strong></p>"
		msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
		w.Write([]byte(msg))
	}
	http.Handle(loginPath, rp.AuthURLHandler(stateProvider, relyingParty))
	http.Handle(callbackPath, rp.CodeExchangeHandler(callback, relyingParty))

	utils.StartServer(codeflowCtx, ":"+port)

	utils.OpenBrowser("http://localhost:" + port + loginPath)

	return <-tokenChan
}

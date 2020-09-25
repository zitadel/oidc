package client

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/rp"
	"github.com/caos/oidc/pkg/utils"
)

var (
	callbackPath string = "/auth/callback"
	key          []byte = []byte("test1234test1234")
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	issuer := os.Getenv("ISSUER")
	port := os.Getenv("PORT")

	ctx := context.Background()

	redirectURI := fmt.Sprintf("http://localhost:%v%v", port, callbackPath)
	scopes := []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeAddress, "hodor"}
	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	provider, err := rp.NewRelayingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes,
		rp.WithPKCE(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second)),
	)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}
}

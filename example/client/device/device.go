// Command device is an example Oauth2 Device Authorization Grant app.
// It creates a new Device Authorization request on the Issuer and then polls for tokens.
// The user is then prompted to visit a URL and enter the user code.
// Or, the complete URL can be used instead to omit manual entry.
// In practice then can be a "magic link" in the form or a QR.
//
// The following environment variables are used for configuration:
//
//	ISSUER: URL to the OP, required.
//	CLIENT_ID: ID of the application, required.
//	CLIENT_SECRET: Secret to authenticate the app using basic auth. Only required if the OP expects this type of authentication.
//	KEY_PATH: Path to a private key file, used to for JWT authentication of the App. Only required if the OP expects this type of authentication.
//	SCOPES: Scopes of the Authentication Request. Optional.
//
// Basic usage:
//
//	cd example/client/device
//	export ISSUER="http://localhost:9000" CLIENT_ID="246048465824634593@demo"
//
// Get an Access Token:
//
//	SCOPES="email profile" go run .
//
// Get an Access Token and ID Token:
//
//	SCOPES="email profile openid" go run .
//
// Get an Access Token and Refresh Token
//
//	SCOPES="email profile offline_access" go run .
//
// Get Access, Refresh and ID Tokens:
//
//	SCOPES="email profile offline_access openid" go run .
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

var (
	key = []byte("test1234test1234")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT)
	defer stop()

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	keyPath := os.Getenv("KEY_PATH")
	issuer := os.Getenv("ISSUER")
	scopes := strings.Split(os.Getenv("SCOPES"), " ")

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	var options []rp.Option
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, "", scopes, options...)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	logrus.Info("starting device authorization flow")
	resp, err := rp.DeviceAuthorization(ctx, scopes, provider, nil)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Info("resp", resp)
	fmt.Printf("\nPlease browse to %s and enter code %s\n", resp.VerificationURI, resp.UserCode)

	logrus.Info("start polling")
	token, err := rp.DeviceAccessToken(ctx, resp.DeviceCode, time.Duration(resp.Interval)*time.Second, provider)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("successfully obtained token: %#v", token)
}

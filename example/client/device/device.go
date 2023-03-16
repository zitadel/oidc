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

	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
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

	provider, err := rp.NewRelyingPartyOIDC(issuer, clientID, clientSecret, "", scopes, options...)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	logrus.Info("starting device authorization flow")
	resp, err := rp.DeviceAuthorization(scopes, provider)
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
	logrus.Infof("successfully obtained token: %v", token)
}

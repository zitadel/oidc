package cli

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	loginPath = "/login"
)

func CodeFlow[C oidc.IDClaims](ctx context.Context, relyingParty rp.RelyingParty, callbackPath, port string, stateProvider func() string) *oidc.Tokens[C] {
	codeflowCtx, codeflowCancel := context.WithCancel(ctx)
	defer codeflowCancel()

	tokenChan := make(chan *oidc.Tokens[C], 1)

	callback := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], state string, rp rp.RelyingParty) {
		tokenChan <- tokens
		msg := "<p><strong>Success!</strong></p>"
		msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
		w.Write([]byte(msg))
	}
	http.Handle(loginPath, rp.AuthURLHandler(stateProvider, relyingParty))
	http.Handle(callbackPath, rp.CodeExchangeHandler(callback, relyingParty))

	listenAddress, loginURL, err := callbackServerConfig(relyingParty.OAuthConfig().RedirectURL, callbackPath, port)
	if err != nil {
		log.Fatalf("invalid redirect URI: %v", err)
	}
	httphelper.StartServer(codeflowCtx, listenAddress)

	OpenBrowser(loginURL)

	return <-tokenChan
}

func callbackServerConfig(redirectURI, callbackPath, port string) (listenAddress, loginURL string, err error) {
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(redirect.Scheme, "http") {
		return "", "", fmt.Errorf("scheme must be http")
	}
	if redirect.User != nil {
		return "", "", fmt.Errorf("user information is not allowed")
	}
	if redirect.Fragment != "" {
		return "", "", fmt.Errorf("fragment is not allowed")
	}
	if redirect.Path != callbackPath {
		return "", "", fmt.Errorf("callback path %q does not match redirect URI path %q", callbackPath, redirect.Path)
	}

	host := redirect.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("host is required")
	}
	redirectPort := redirect.Port()
	if redirectPort == "" {
		return "", "", fmt.Errorf("port is required")
	}
	if port != redirectPort {
		return "", "", fmt.Errorf("port %q does not match redirect URI port %q", port, redirectPort)
	}

	listenHost := host
	if strings.EqualFold(host, "localhost") {
		// Preserve the existing dual-stack behavior for localhost. Callers should
		// prefer an explicit loopback IP to avoid address-family ambiguity.
		listenHost = ""
	} else if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", "", fmt.Errorf("host %q is not a loopback address", host)
	}

	listenAddress = net.JoinHostPort(listenHost, redirectPort)
	login := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, redirectPort),
		Path:   loginPath,
	}
	return listenAddress, login.String(), nil
}

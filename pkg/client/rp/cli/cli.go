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

const defaultSuccessHTML = "<p><strong>Success!</strong></p>" +
	"<p>You are authenticated and can now return to the CLI.</p>"

// CodeFlowOpt configures [CodeFlowWithOptions].
type CodeFlowOpt func(*codeFlowConfig)

type codeFlowConfig struct {
	authURLParams      []rp.URLParamOpt
	codeExchangeParams []rp.URLParamOpt
	successHTML        string
}

// WithAuthURLParams adds parameters to the authorization request sent from the
// login handler, for example rp.WithURLParam("audience", "https://api.example.com")
// for providers such as Auth0 that only issue a JWT access token for a named audience.
func WithAuthURLParams(params ...rp.URLParamOpt) CodeFlowOpt {
	return func(c *codeFlowConfig) {
		c.authURLParams = append(c.authURLParams, params...)
	}
}

// WithCodeExchangeParams adds parameters to the token request made by the
// callback handler.
func WithCodeExchangeParams(params ...rp.URLParamOpt) CodeFlowOpt {
	return func(c *codeFlowConfig) {
		c.codeExchangeParams = append(c.codeExchangeParams, params...)
	}
}

// WithSuccessHTML replaces the HTML page shown in the browser after a successful
// login, for example to close the window with
// `<body onload="window.close()">You may close this window</body>`.
func WithSuccessHTML(html string) CodeFlowOpt {
	return func(c *codeFlowConfig) {
		c.successHTML = html
	}
}

// CodeFlow runs the authorization code flow for a CLI with a local callback
// server and returns the tokens. Use [CodeFlowWithOptions] to customise it.
func CodeFlow[C oidc.IDClaims](ctx context.Context, relyingParty rp.RelyingParty, callbackPath, port string, stateProvider func() string) *oidc.Tokens[C] {
	return CodeFlowWithOptions[C](ctx, relyingParty, callbackPath, port, stateProvider)
}

// CodeFlowWithOptions is [CodeFlow] with options for the authorization request,
// the token request and the page shown after login.
func CodeFlowWithOptions[C oidc.IDClaims](ctx context.Context, relyingParty rp.RelyingParty, callbackPath, port string, stateProvider func() string, opts ...CodeFlowOpt) *oidc.Tokens[C] {
	codeflowCtx, codeflowCancel := context.WithCancel(ctx)
	defer codeflowCancel()

	tokenChan := make(chan *oidc.Tokens[C], 1)

	login, callback := codeFlowHandlers(relyingParty, stateProvider, tokenChan, opts...)
	http.Handle(loginPath, login)
	http.Handle(callbackPath, callback)

	listenAddress, loginURL, err := callbackServerConfig(relyingParty.OAuthConfig().RedirectURL, callbackPath, port)
	if err != nil {
		log.Fatalf("invalid redirect URI: %v", err)
	}
	httphelper.StartServer(codeflowCtx, listenAddress)

	OpenBrowser(loginURL)

	return <-tokenChan
}

// codeFlowHandlers returns the login and callback handlers of the CLI code flow.
// The callback handler sends the tokens to tokenChan.
func codeFlowHandlers[C oidc.IDClaims](relyingParty rp.RelyingParty, stateProvider func() string, tokenChan chan<- *oidc.Tokens[C], opts ...CodeFlowOpt) (login, callback http.Handler) {
	cfg := codeFlowConfig{successHTML: defaultSuccessHTML}
	for _, opt := range opts {
		opt(&cfg)
	}

	onTokens := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], state string, rp rp.RelyingParty) {
		tokenChan <- tokens
		w.Write([]byte(cfg.successHTML))
	}
	login = rp.AuthURLHandler(stateProvider, relyingParty, cfg.authURLParams...)
	callback = rp.CodeExchangeHandler(onTokens, relyingParty, cfg.codeExchangeParams...)
	return login, callback
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

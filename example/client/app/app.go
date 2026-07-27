package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	callbackPath = "/auth/callback"
	key          = []byte("test1234test1234")
	requestCount atomic.Uint64
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	keyPath := os.Getenv("KEY_PATH")
	keyID := os.Getenv("KEY_ID")
	issuer := os.Getenv("ISSUER")
	port := os.Getenv("PORT")
	scopes := strings.Split(os.Getenv("SCOPES"), " ")
	responseMode := os.Getenv("RESPONSE_MODE")

	var pkce bool
	if pkceEnv, ok := os.LookupEnv("PKCE"); ok {
		var err error
		pkce, err = strconv.ParseBool(pkceEnv)
		if err != nil {
			slog.Error("error parsing PKCE", "error", err)
			os.Exit(1)
		}
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%v%v", port, callbackPath)
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)
	slog.SetDefault(logger)
	client := &http.Client{
		Timeout:   time.Minute,
		Transport: loggingRoundTripper{base: http.DefaultTransport},
	}

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(client),
		rp.WithSigningAlgsFromDiscovery(),
	}
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if keyPath != "" {
		signingKey, err := os.ReadFile(keyPath)
		if err != nil {
			slog.Error("error reading key file", "error", err)
			os.Exit(1)
		}
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyAndKeyID(signingKey, keyID)))
	}
	if pkce {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	ctx := context.TODO()
	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		slog.Error("error creating provider", "error", err)
		os.Exit(1)
	}

	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	state := func() string {
		return uuid.New().String()
	}

	urlOptions := []rp.URLParamOpt{
		rp.WithPromptURLParam("Welcome back!"),
	}

	if responseMode != "" {
		urlOptions = append(urlOptions, rp.WithResponseModeURLParam(oidc.ResponseMode(responseMode)))
	}

	// register the AuthURLHandler at your preferred path.
	// the AuthURLHandler creates the auth request and redirects the user to the auth server.
	// including state handling with secure cookie and the possibility to use PKCE.
	// Prompts can optionally be set to inform the server of
	// any messages that need to be prompted back to the user.
	http.Handle("/login", rp.AuthURLHandler(
		state,
		provider,
		urlOptions...,
	))

	// for demonstration purposes the returned userinfo response is written as JSON object onto response
	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		fmt.Println("access token", tokens.AccessToken)
		fmt.Println("refresh token", tokens.RefreshToken)
		fmt.Println("id token", tokens.IDToken)

		data, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Write(data)
	}

	// you could also just take the access_token and id_token without calling the userinfo endpoint:
	//
	// marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
	//	data, err := json.Marshal(tokens)
	//	if err != nil {
	//		http.Error(w, err.Error(), http.StatusInternalServerError)
	//		return
	//	}
	//	w.Write(data)
	//}

	// you can also try token exchange flow
	//
	// requestTokenExchange := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty, info oidc.UserInfo) {
	// 	data := make(url.Values)
	// 	data.Set("grant_type", string(oidc.GrantTypeTokenExchange))
	// 	data.Set("requested_token_type", string(oidc.IDTokenType))
	// 	data.Set("subject_token", tokens.RefreshToken)
	// 	data.Set("subject_token_type", string(oidc.RefreshTokenType))
	// 	data.Add("scope", "profile custom_scope:impersonate:id2")

	// 	client := &http.Client{}
	// 	r2, _ := http.NewRequest(http.MethodPost, issuer+"/oauth/token", strings.NewReader(data.Encode()))
	// 	// r2.Header.Add("Authorization", "Basic "+"d2ViOnNlY3JldA==")
	// 	r2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// 	r2.SetBasicAuth("web", "secret")

	// 	resp, _ := client.Do(r2)
	// 	fmt.Println(resp.Status)

	// 	b, _ := io.ReadAll(resp.Body)
	// 	resp.Body.Close()

	// 	w.Write(b)
	// }

	// register the CodeExchangeHandler at the callbackPath
	// the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
	// with the returned tokens from the token endpoint
	// in this example the callback function itself is wrapped by the UserinfoCallback which
	// will call the Userinfo endpoint, check the sub and pass the info into the callback function
	http.Handle(callbackPath, rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), provider))

	// if you would use the callback without calling the userinfo endpoint, simply switch the callback handler for:
	//
	// http.Handle(callbackPath, rp.CodeExchangeHandler(marshalToken, provider))

	lis := fmt.Sprintf("127.0.0.1:%s", port)
	slog.Info("server listening, press ctrl+c to stop", "addr", lis)
	err = http.ListenAndServe(lis, requestLoggingMiddleware(http.DefaultServeMux))
	if err != http.ErrServerClosed {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

// requestLoggingMiddleware demonstrates request IDs and structured incoming
// request logs using only the standard library.
func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := requestCount.Add(1)
		w.Header().Set("X-Request-ID", strconv.FormatUint(requestID, 10))
		started := time.Now()

		next.ServeHTTP(w, r)

		slog.InfoContext(r.Context(), "http request",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(started),
		)
	})
}

// loggingRoundTripper demonstrates lightweight tracing of outbound discovery
// and token requests. A production application could replace this with its
// preferred tracing transport.
type loggingRoundTripper struct {
	base http.RoundTripper
}

func (t loggingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	started := time.Now()
	response, err := t.base.RoundTrip(r)
	if err != nil {
		slog.DebugContext(r.Context(), "http client request",
			"method", r.Method,
			"host", r.URL.Host,
			"path", r.URL.Path,
			"duration", time.Since(started),
			"error", err,
		)
		return nil, err
	}
	slog.DebugContext(r.Context(), "http client request",
		"method", r.Method,
		"host", r.URL.Host,
		"path", r.URL.Path,
		"status_code", response.StatusCode,
		"duration", time.Since(started),
	)
	return response, nil
}

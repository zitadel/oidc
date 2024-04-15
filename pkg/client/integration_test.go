package client_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/jeremija/gosubmit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/example/server/exampleop"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/client/tokenexchange"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var Logger = slog.New(
	slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}),
)

var CTX context.Context

func TestMain(m *testing.M) {
	os.Exit(func() int {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT)
		defer cancel()
		CTX, cancel = context.WithTimeout(ctx, time.Minute)
		defer cancel()
		return m.Run()
	}())
}

func TestRelyingPartySession(t *testing.T) {
	for _, wrapServer := range []bool{false, true} {
		t.Run(fmt.Sprint("wrapServer ", wrapServer), func(t *testing.T) {
			testRelyingPartySession(t, wrapServer)
		})
	}
}

func testRelyingPartySession(t *testing.T, wrapServer bool) {
	t.Log("------- start example OP ------")
	targetURL := "http://local-site"
	exampleStorage := storage.NewStorage(storage.NewUserStore(targetURL))
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	defer opServer.Close()
	t.Logf("auth server at %s", opServer.URL)
	dh.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, wrapServer)

	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	clientID := t.Name() + "-" + strconv.FormatInt(seed.Int63(), 25)

	t.Log("------- run authorization code flow ------")
	provider, tokens := RunAuthorizationCodeFlow(t, opServer, clientID, "secret")

	t.Log("------- refresh tokens  ------")

	newTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](CTX, provider, tokens.RefreshToken, "", "")
	require.NoError(t, err, "refresh token")
	assert.NotNil(t, newTokens, "access token")
	t.Logf("new access token %s", newTokens.AccessToken)
	t.Logf("new refresh token %s", newTokens.RefreshToken)
	t.Logf("new token type %s", newTokens.TokenType)
	t.Logf("new expiry %s", newTokens.Expiry.Format(time.RFC3339))
	require.NotEmpty(t, newTokens.AccessToken, "new accessToken")
	assert.NotEmpty(t, newTokens.IDToken, "new idToken")
	assert.NotNil(t, newTokens.IDTokenClaims)
	assert.Equal(t, newTokens.IDTokenClaims.Subject, tokens.IDTokenClaims.Subject)

	t.Log("------ end session (logout) ------")

	newLoc, err := rp.EndSession(CTX, provider, tokens.IDToken, "", "")
	require.NoError(t, err, "logout")
	if newLoc != nil {
		t.Logf("redirect to %s", newLoc)
	} else {
		t.Logf("no redirect")
	}

	t.Log("------ attempt refresh again (should fail) ------")
	t.Log("trying original refresh token", tokens.RefreshToken)
	_, err = rp.RefreshTokens[*oidc.IDTokenClaims](CTX, provider, tokens.RefreshToken, "", "")
	assert.Errorf(t, err, "refresh with original")
	if newTokens.RefreshToken != "" {
		t.Log("trying replacement refresh token", newTokens.RefreshToken)
		_, err = rp.RefreshTokens[*oidc.IDTokenClaims](CTX, provider, newTokens.RefreshToken, "", "")
		assert.Errorf(t, err, "refresh with replacement")
	}
}

func TestRelyingPartyWithSigningAlgsFromDiscovery(t *testing.T) {
	targetURL := "http://local-site"
	localURL, err := url.Parse(targetURL + "/login?requestID=1234")
	require.NoError(t, err, "local url")

	t.Log("------- start example OP ------")
	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	clientID := t.Name() + "-" + strconv.FormatInt(seed.Int63(), 25)
	clientSecret := "secret"
	client := storage.WebClient(clientID, clientSecret, targetURL)
	storage.RegisterClients(client)
	exampleStorage := storage.NewStorage(storage.NewUserStore(targetURL))
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	defer opServer.Close()
	dh.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, true)

	t.Log("------- create RP ------")
	provider, err := rp.NewRelyingPartyOIDC(
		CTX,
		opServer.URL,
		clientID,
		clientSecret,
		targetURL,
		[]string{"openid"},
		rp.WithSigningAlgsFromDiscovery(),
	)
	require.NoError(t, err, "new rp")

	t.Log("------- run authorization code flow ------")
	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "create cookie jar")
	httpClient := &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}
	state := "state-" + strconv.FormatInt(seed.Int63(), 25)
	capturedW := httptest.NewRecorder()
	get := httptest.NewRequest("GET", localURL.String(), nil)
	rp.AuthURLHandler(func() string { return state }, provider,
		rp.WithPromptURLParam("Hello, World!", "Goodbye, World!"),
		rp.WithURLParam("custom", "param"),
	)(capturedW, get)
	defer func() {
		if t.Failed() {
			t.Log("response body (redirect from RP to OP)", capturedW.Body.String())
		}
	}()
	resp := capturedW.Result()
	startAuthURL, err := resp.Location()
	require.NoError(t, err, "get redirect")
	loginPageURL := getRedirect(t, "get redirect to login page", httpClient, startAuthURL)
	form := getForm(t, "get login form", httpClient, loginPageURL)
	defer func() {
		if t.Failed() {
			t.Logf("login form (unfilled): %s", string(form))
		}
	}()
	postLoginRedirectURL := fillForm(t, "fill login form", httpClient, form, loginPageURL,
		gosubmit.Set("username", "test-user@local-site"),
		gosubmit.Set("password", "verysecure"),
	)
	codeBearingURL := getRedirect(t, "get redirect with code", httpClient, postLoginRedirectURL)
	capturedW = httptest.NewRecorder()
	get = httptest.NewRequest("GET", codeBearingURL.String(), nil)
	var idToken string
	redirect := func(w http.ResponseWriter, r *http.Request, newTokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		idToken = newTokens.IDToken
		http.Redirect(w, r, targetURL, http.StatusFound)
	}
	rp.CodeExchangeHandler(rp.UserinfoCallback(redirect), provider)(capturedW, get)
	defer func() {
		if t.Failed() {
			t.Log("token exchange response body", capturedW.Body.String())
			require.GreaterOrEqual(t, capturedW.Code, 200, "captured response code")
		}
	}()

	t.Log("------- verify id token ------")
	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](CTX, idToken, provider.IDTokenVerifier())
	require.NoError(t, err, "verify id token")
}

func TestResourceServerTokenExchange(t *testing.T) {
	for _, wrapServer := range []bool{false, true} {
		t.Run(fmt.Sprint("wrapServer ", wrapServer), func(t *testing.T) {
			testResourceServerTokenExchange(t, wrapServer)
		})
	}
}

func testResourceServerTokenExchange(t *testing.T, wrapServer bool) {
	t.Log("------- start example OP ------")
	targetURL := "http://local-site"
	exampleStorage := storage.NewStorage(storage.NewUserStore(targetURL))
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	defer opServer.Close()
	t.Logf("auth server at %s", opServer.URL)
	dh.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, wrapServer)

	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	clientID := t.Name() + "-" + strconv.FormatInt(seed.Int63(), 25)
	clientSecret := "secret"

	t.Log("------- run authorization code flow ------")
	provider, tokens := RunAuthorizationCodeFlow(t, opServer, clientID, clientSecret)

	resourceServer, err := rs.NewResourceServerClientCredentials(CTX, opServer.URL, clientID, clientSecret)
	require.NoError(t, err, "new resource server")

	t.Log("------- exchage refresh tokens (impersonation)  ------")

	tokenExchangeResponse, err := tokenexchange.ExchangeToken(
		CTX,
		resourceServer,
		tokens.RefreshToken,
		oidc.RefreshTokenType,
		"",
		"",
		[]string{},
		[]string{},
		[]string{"profile", "custom_scope:impersonate:id2"},
		oidc.RefreshTokenType,
	)
	require.NoError(t, err, "refresh token")
	require.NotNil(t, tokenExchangeResponse, "token exchange response")
	assert.Equal(t, tokenExchangeResponse.IssuedTokenType, oidc.RefreshTokenType)
	assert.NotEmpty(t, tokenExchangeResponse.AccessToken, "access token")
	assert.NotEmpty(t, tokenExchangeResponse.RefreshToken, "refresh token")
	assert.Equal(t, []string(tokenExchangeResponse.Scopes), []string{"profile", "custom_scope:impersonate:id2"})

	t.Log("------ end session (logout) ------")

	newLoc, err := rp.EndSession(CTX, provider, tokens.IDToken, "", "")
	require.NoError(t, err, "logout")
	if newLoc != nil {
		t.Logf("redirect to %s", newLoc)
	} else {
		t.Logf("no redirect")
	}

	t.Log("------- attempt exchage again (should fail)  ------")

	tokenExchangeResponse, err = tokenexchange.ExchangeToken(
		CTX,
		resourceServer,
		tokens.RefreshToken,
		oidc.RefreshTokenType,
		"",
		"",
		[]string{},
		[]string{},
		[]string{"profile", "custom_scope:impersonate:id2"},
		oidc.RefreshTokenType,
	)
	require.Error(t, err, "refresh token")
	assert.Contains(t, err.Error(), "subject_token is invalid")
	require.Nil(t, tokenExchangeResponse, "token exchange response")
}

func RunAuthorizationCodeFlow(t *testing.T, opServer *httptest.Server, clientID, clientSecret string) (provider rp.RelyingParty, tokens *oidc.Tokens[*oidc.IDTokenClaims]) {
	targetURL := "http://local-site"
	localURL, err := url.Parse(targetURL + "/login?requestID=1234")
	require.NoError(t, err, "local url")

	client := storage.WebClient(clientID, clientSecret, targetURL)
	storage.RegisterClients(client)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "create cookie jar")
	httpClient := &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}

	t.Log("------- create RP ------")
	key := []byte("test1234test1234")
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	provider, err = rp.NewRelyingPartyOIDC(
		CTX,
		opServer.URL,
		clientID,
		clientSecret,
		targetURL,
		[]string{"openid", "email", "profile", "offline_access"},
		rp.WithPKCE(cookieHandler),
		rp.WithAuthStyle(oauth2.AuthStyleInHeader),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(5*time.Second),
			rp.WithSupportedSigningAlgorithms("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"),
		),
	)
	require.NoError(t, err, "new rp")

	t.Log("------- get redirect from local client (rp) to OP ------")
	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	state := "state-" + strconv.FormatInt(seed.Int63(), 25)
	capturedW := httptest.NewRecorder()
	get := httptest.NewRequest("GET", localURL.String(), nil)
	rp.AuthURLHandler(func() string { return state }, provider,
		rp.WithPromptURLParam("Hello, World!", "Goodbye, World!"),
		rp.WithURLParam("custom", "param"),
	)(capturedW, get)

	defer func() {
		if t.Failed() {
			t.Log("response body (redirect from RP to OP)", capturedW.Body.String())
		}
	}()
	require.GreaterOrEqual(t, capturedW.Code, 200, "captured response code")
	require.Less(t, capturedW.Code, 400, "captured response code")
	require.Contains(t, capturedW.Body.String(), `prompt=Hello%2C+World%21+Goodbye%2C+World%21`)
	require.Contains(t, capturedW.Body.String(), `custom=param`)

	//nolint:bodyclose
	resp := capturedW.Result()
	jar.SetCookies(localURL, resp.Cookies())

	startAuthURL, err := resp.Location()
	require.NoError(t, err, "get redirect")
	assert.NotEmpty(t, startAuthURL, "login url")
	t.Log("Starting auth at", startAuthURL)

	t.Log("------- get redirect to OP to login page ------")
	loginPageURL := getRedirect(t, "get redirect to login page", httpClient, startAuthURL)
	t.Log("login page URL", loginPageURL)

	t.Log("------- get login form ------")
	form := getForm(t, "get login form", httpClient, loginPageURL)
	t.Log("login form (unfilled)", string(form))
	defer func() {
		if t.Failed() {
			t.Logf("login form (unfilled): %s", string(form))
		}
	}()

	t.Log("------- post to login form, get redirect to OP ------")
	postLoginRedirectURL := fillForm(t, "fill login form", httpClient, form, loginPageURL,
		gosubmit.Set("username", "test-user@local-site"),
		gosubmit.Set("password", "verysecure"))
	t.Logf("Get redirect from %s", postLoginRedirectURL)

	t.Log("------- redirect from OP back to RP ------")
	codeBearingURL := getRedirect(t, "get redirect with code", httpClient, postLoginRedirectURL)
	t.Logf("Redirect with code %s", codeBearingURL)

	t.Log("------- exchange code for tokens ------")
	capturedW = httptest.NewRecorder()
	get = httptest.NewRequest("GET", codeBearingURL.String(), nil)
	for _, cookie := range jar.Cookies(codeBearingURL) {
		get.Header["Cookie"] = append(get.Header["Cookie"], cookie.String())
		t.Logf("setting cookie %s", cookie)
	}

	var email string
	redirect := func(w http.ResponseWriter, r *http.Request, newTokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		tokens = newTokens
		require.NotNil(t, tokens, "tokens")
		require.NotNil(t, info, "info")
		t.Log("access token", tokens.AccessToken)
		t.Log("refresh token", tokens.RefreshToken)
		t.Log("id token", tokens.IDToken)
		t.Log("email", info.Email)

		email = info.Email
		http.Redirect(w, r, targetURL, 302)
	}
	rp.CodeExchangeHandler(rp.UserinfoCallback(redirect), provider, rp.WithURLParam("custom", "param"))(capturedW, get)

	defer func() {
		if t.Failed() {
			t.Log("token exchange response body", capturedW.Body.String())
			require.GreaterOrEqual(t, capturedW.Code, 200, "captured response code")
		}
	}()
	require.Less(t, capturedW.Code, 400, "token exchange response code")
	// TODO: how to check the custom header was sent to the server?

	//nolint:bodyclose
	resp = capturedW.Result()

	authorizedURL, err := resp.Location()
	require.NoError(t, err, "get fully-authorizied redirect location")
	require.Equal(t, targetURL, authorizedURL.String(), "fully-authorizied redirect location")

	require.NotEmpty(t, tokens.IDToken, "id token")
	assert.NotEmpty(t, tokens.RefreshToken, "refresh token")
	assert.NotEmpty(t, tokens.AccessToken, "access token")
	assert.NotEmpty(t, email, "email")

	return provider, tokens
}

func TestClientCredentials(t *testing.T) {
	targetURL := "http://local-site"
	exampleStorage := storage.NewStorage(storage.NewUserStore(targetURL))
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	defer opServer.Close()
	t.Logf("auth server at %s", opServer.URL)
	dh.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, true)

	provider, err := rp.NewRelyingPartyOIDC(
		CTX,
		opServer.URL,
		"sid1",
		"verysecret",
		targetURL,
		[]string{"openid"},
	)
	require.NoError(t, err, "new rp")

	token, err := rp.ClientCredentials(CTX, provider, nil)
	require.NoError(t, err, "ClientCredentials call")
	require.NotNil(t, token)
	assert.NotEmpty(t, token.AccessToken)
}

func TestErrorFromPromptNone(t *testing.T) {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "create cookie jar")
	httpClient := &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}

	t.Log("------- start example OP ------")
	targetURL := "http://local-site"
	exampleStorage := storage.NewStorage(storage.NewUserStore(targetURL))
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	defer opServer.Close()
	t.Logf("auth server at %s", opServer.URL)
	dh.Handler = exampleop.SetupServer(opServer.URL, exampleStorage, Logger, false, op.WithHttpInterceptors(
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("request to %s", r.URL)
				next.ServeHTTP(w, r)
			})
		},
	))
	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	clientID := t.Name() + "-" + strconv.FormatInt(seed.Int63(), 25)
	clientSecret := "secret"
	client := storage.WebClient(clientID, clientSecret, targetURL)
	storage.RegisterClients(client)

	t.Log("------- create RP ------")
	key := []byte("test1234test1234")
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	provider, err := rp.NewRelyingPartyOIDC(
		CTX,
		opServer.URL,
		clientID,
		clientSecret,
		targetURL,
		[]string{"openid", "email", "profile", "offline_access"},
		rp.WithPKCE(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(5*time.Second),
			rp.WithSupportedSigningAlgorithms("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"),
		),
	)
	require.NoError(t, err, "new rp")

	t.Log("------- start auth flow with prompt=none ------- ")
	state := "state-32892"
	capturedW := httptest.NewRecorder()
	localURL, err := url.Parse(targetURL + "/login")
	require.NoError(t, err)

	get := httptest.NewRequest("GET", localURL.String(), nil)
	rp.AuthURLHandler(func() string { return state }, provider,
		rp.WithPromptURLParam("none"),
		rp.WithResponseModeURLParam(oidc.ResponseModeFragment),
	)(capturedW, get)

	defer func() {
		if t.Failed() {
			t.Log("response body (redirect from RP to OP)", capturedW.Body.String())
		}
	}()
	require.GreaterOrEqual(t, capturedW.Code, 200, "captured response code")
	require.Less(t, capturedW.Code, 400, "captured response code")

	//nolint:bodyclose
	resp := capturedW.Result()
	jar.SetCookies(localURL, resp.Cookies())

	startAuthURL, err := resp.Location()
	require.NoError(t, err, "get redirect")
	assert.NotEmpty(t, startAuthURL, "login url")
	t.Log("Starting auth at", startAuthURL)

	t.Log("------- get redirect from OP ------")
	loginPageURL := getRedirect(t, "get redirect to login page", httpClient, startAuthURL)
	t.Log("login page URL", loginPageURL)

	require.Contains(t, loginPageURL.String(), `error=login_required`, "prompt=none should error")
	require.Contains(t, loginPageURL.String(), `local-site#error=`, "response_mode=fragment means '#' instead of '?'")
}

type deferredHandler struct {
	http.Handler
}

func getRedirect(t *testing.T, desc string, httpClient *http.Client, uri *url.URL) *url.URL {
	req := &http.Request{
		Method: "GET",
		URL:    uri,
		Header: make(http.Header),
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err, "GET "+uri.String())

	defer func() {
		if t.Failed() {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("%s: GET %s: body: %s", desc, uri, string(body))
		}
	}()

	//nolint:errcheck
	defer resp.Body.Close()
	redirect, err := resp.Location()
	require.NoErrorf(t, err, "%s: get redirect %s", desc, uri)
	require.NotEmptyf(t, redirect, "%s: get redirect %s", desc, uri)
	return redirect
}

func getForm(t *testing.T, desc string, httpClient *http.Client, uri *url.URL) []byte {
	req := &http.Request{
		Method: "GET",
		URL:    uri,
		Header: make(http.Header),
	}
	resp, err := httpClient.Do(req)
	require.NoErrorf(t, err, "%s: GET %s", desc, uri)
	//nolint:errcheck
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "%s: read GET %s", desc, uri)
	return body
}

func fillForm(t *testing.T, desc string, httpClient *http.Client, body []byte, uri *url.URL, opts ...gosubmit.Option) *url.URL {
	// TODO: switch to io.NopCloser when go1.15 support is dropped
	req := gosubmit.ParseWithURL(io.NopCloser(bytes.NewReader(body)), uri.String()).FirstForm().Testing(t).NewTestRequest(
		append([]gosubmit.Option{gosubmit.AutoFill()}, opts...)...,
	)
	if req.URL.Scheme == "" {
		req.URL = uri
		t.Log("request lost it's proto..., adding back... request now", req.URL)
	}
	req.RequestURI = "" // bug in gosubmit?
	resp, err := httpClient.Do(req)
	require.NoErrorf(t, err, "%s: POST %s", desc, uri)

	//nolint:errcheck
	defer resp.Body.Close()
	defer func() {
		if t.Failed() {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("%s: GET %s: body: %s", desc, uri, string(body))
		}
	}()

	redirect, err := resp.Location()
	require.NoErrorf(t, err, "%s: redirect for POST %s", desc, uri)
	return redirect
}

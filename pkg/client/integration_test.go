package client_test

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jeremija/gosubmit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v2/example/server/exampleop"
	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/client/rs"
	"github.com/zitadel/oidc/v2/pkg/client/tokenexchange"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func TestRelyingPartySession(t *testing.T) {
	t.Log("------- start example OP ------")
	ctx := context.Background()
	targetURL := "http://local-site"
	exampleStorage := storage.NewStorage(storage.NewUserStore(targetURL))
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	defer opServer.Close()
	t.Logf("auth server at %s", opServer.URL)
	dh.Handler = exampleop.SetupServer(ctx, opServer.URL, exampleStorage)

	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	clientID := t.Name() + "-" + strconv.FormatInt(seed.Int63(), 25)

	t.Log("------- run authorization code flow ------")
	provider, _, refreshToken, idToken := RunAuthorizationCodeFlow(t, opServer, clientID, "secret")

	t.Log("------- refresh tokens  ------")

	newTokens, err := rp.RefreshAccessToken(provider, refreshToken, "", "")
	require.NoError(t, err, "refresh token")
	assert.NotNil(t, newTokens, "access token")
	t.Logf("new access token %s", newTokens.AccessToken)
	t.Logf("new refresh token %s", newTokens.RefreshToken)
	t.Logf("new token type %s", newTokens.TokenType)
	t.Logf("new expiry %s", newTokens.Expiry.Format(time.RFC3339))
	require.NotEmpty(t, newTokens.AccessToken, "new accessToken")

	t.Log("------ end session (logout) ------")

	newLoc, err := rp.EndSession(provider, idToken, "", "")
	require.NoError(t, err, "logout")
	if newLoc != nil {
		t.Logf("redirect to %s", newLoc)
	} else {
		t.Logf("no redirect")
	}

	t.Log("------ attempt refresh again (should fail) ------")
	t.Log("trying original refresh token", refreshToken)
	_, err = rp.RefreshAccessToken(provider, refreshToken, "", "")
	assert.Errorf(t, err, "refresh with original")
	if newTokens.RefreshToken != "" {
		t.Log("trying replacement refresh token", newTokens.RefreshToken)
		_, err = rp.RefreshAccessToken(provider, newTokens.RefreshToken, "", "")
		assert.Errorf(t, err, "refresh with replacement")
	}
}

func TestResourceServerTokenExchange(t *testing.T) {
	t.Log("------- start example OP ------")
	ctx := context.Background()
	exampleStorage := storage.NewStorage(storage.NewUserStore())
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	defer opServer.Close()
	t.Logf("auth server at %s", opServer.URL)
	dh.Handler = exampleop.SetupServer(ctx, opServer.URL, exampleStorage)

	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	clientID := t.Name() + "-" + strconv.FormatInt(seed.Int63(), 25)
	clientSecret := "secret"

	t.Log("------- run authorization code flow ------")
	provider, _, refreshToken, idToken := RunAuthorizationCodeFlow(t, opServer, clientID, clientSecret)

	resourceServer, err := rs.NewResourceServerClientCredentials(opServer.URL, clientID, clientSecret)
	require.NoError(t, err, "new resource server")

	t.Log("------- exchage refresh tokens (impersonation)  ------")

	tokenExchangeResponse, err := tokenexchange.ExchangeToken(
		resourceServer,
		refreshToken,
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

	newLoc, err := rp.EndSession(provider, idToken, "", "")
	require.NoError(t, err, "logout")
	if newLoc != nil {
		t.Logf("redirect to %s", newLoc)
	} else {
		t.Logf("no redirect")
	}

	t.Log("------- attempt exchage again (should fail)  ------")

	tokenExchangeResponse, err = tokenexchange.ExchangeToken(
		resourceServer,
		refreshToken,
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

func RunAuthorizationCodeFlow(t *testing.T, opServer *httptest.Server, clientID, clientSecret string) (provider rp.RelyingParty, accessToken, refreshToken, idToken string) {
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

	t.Log("------- get redirect from local client (rp) to OP ------")
	seed := rand.New(rand.NewSource(int64(os.Getpid()) + time.Now().UnixNano()))
	state := "state-" + strconv.FormatInt(seed.Int63(), 25)
	capturedW := httptest.NewRecorder()
	get := httptest.NewRequest("GET", localURL.String(), nil)
	rp.AuthURLHandler(func() string { return state }, provider)(capturedW, get)

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
	redirect := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty, info oidc.UserInfo) {
		require.NotNil(t, tokens, "tokens")
		require.NotNil(t, info, "info")
		t.Log("access token", tokens.AccessToken)
		t.Log("refresh token", tokens.RefreshToken)
		t.Log("id token", tokens.IDToken)
		t.Log("email", info.GetEmail())

		accessToken = tokens.AccessToken
		refreshToken = tokens.RefreshToken
		idToken = tokens.IDToken
		email = info.GetEmail()
		http.Redirect(w, r, targetURL, http.StatusFound)
	}
	rp.CodeExchangeHandler(rp.UserinfoCallback(redirect), provider)(capturedW, get)

	defer func() {
		if t.Failed() {
			t.Log("token exchange response body", capturedW.Body.String())
			require.GreaterOrEqual(t, capturedW.Code, 200, "captured response code")
		}
	}()
	require.Less(t, capturedW.Code, 400, "token exchange response code")
	require.Less(t, capturedW.Code, 400, "token exchange response code")

	//nolint:bodyclose
	resp = capturedW.Result()

	authorizedURL, err := resp.Location()
	require.NoError(t, err, "get fully-authorizied redirect location")
	require.Equal(t, targetURL, authorizedURL.String(), "fully-authorizied redirect location")

	require.NotEmpty(t, idToken, "id token")
	assert.NotEmpty(t, refreshToken, "refresh token")
	assert.NotEmpty(t, accessToken, "access token")
	assert.NotEmpty(t, email, "email")

	return provider, accessToken, refreshToken, idToken
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
	req := gosubmit.ParseWithURL(ioutil.NopCloser(bytes.NewReader(body)), uri.String()).FirstForm().Testing(t).NewTestRequest(
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

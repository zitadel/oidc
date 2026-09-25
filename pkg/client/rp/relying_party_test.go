package rp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestDeprecatedLoggerCompatibility(t *testing.T) {
	previous := slog.Default()
	configured := slog.New(slog.NewTextHandler(new(strings.Builder), nil))

	rp := &relyingParty{}
	require.NoError(t, WithLogger(configured)(rp))
	assert.Same(t, previous, slog.Default())

	logger, ok := rp.Logger(context.Background())
	assert.Same(t, configured, logger)
	assert.True(t, ok)

	assert.NotPanics(t, func() {
		require.NoError(t, WithLogger(nil)(&relyingParty{}))
	})

	logger, ok = (&relyingParty{}).Logger(context.Background())
	assert.Same(t, previous, logger)
	assert.True(t, ok)
}

func Test_verifyTokenResponse(t *testing.T) {
	verifier := &IDTokenVerifier{
		Issuer:            tu.ValidIssuer,
		MaxAgeIAT:         2 * time.Minute,
		ClientID:          tu.ValidClientID,
		Offset:            time.Second,
		SupportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		KeySet:            tu.KeySet{},
		MaxAge:            2 * time.Minute,
		ACR:               tu.ACRVerify,
		AZP:               oidc.DefaultAZPVerifier(tu.ValidClientID),
		Nonce:             func(context.Context) string { return tu.ValidNonce },
	}
	tests := []struct {
		name       string
		oauth2Only bool
		tokens     func() (token *oauth2.Token, want *oidc.Tokens[*oidc.IDTokenClaims])
		wantErr    error
	}{
		{
			name:       "success, oauth2 only",
			oauth2Only: true,
			tokens: func() (*oauth2.Token, *oidc.Tokens[*oidc.IDTokenClaims]) {
				accessToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accessToken,
				}
				return token, &oidc.Tokens[*oidc.IDTokenClaims]{
					Token: token,
				}
			},
		},
		{
			name:       "id_token missing error",
			oauth2Only: false,
			tokens: func() (*oauth2.Token, *oidc.Tokens[*oidc.IDTokenClaims]) {
				accessToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accessToken,
				}
				return token, &oidc.Tokens[*oidc.IDTokenClaims]{
					Token: token,
				}
			},
			wantErr: ErrMissingIDToken,
		},
		{
			name:       "verify tokens error",
			oauth2Only: false,
			tokens: func() (*oauth2.Token, *oidc.Tokens[*oidc.IDTokenClaims]) {
				accessToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accessToken,
				}
				token = token.WithExtra(map[string]any{
					"id_token": "foobar",
				})
				return token, nil
			},
			wantErr: oidc.ErrParse,
		},
		{
			name:       "success, with id_token",
			oauth2Only: false,
			tokens: func() (*oauth2.Token, *oidc.Tokens[*oidc.IDTokenClaims]) {
				accessToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accessToken,
				}
				idToken, claims := tu.ValidIDToken()
				token = token.WithExtra(map[string]any{
					"id_token": idToken,
				})
				return token, &oidc.Tokens[*oidc.IDTokenClaims]{
					Token:         token,
					IDTokenClaims: claims,
					IDToken:       idToken,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := &relyingParty{
				oauth2Only:      tt.oauth2Only,
				idTokenVerifier: verifier,
			}
			token, want := tt.tokens()
			got, err := verifyTokenResponse[*oidc.IDTokenClaims](context.Background(), token, rp)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, want, got)
		})
	}
}

func Test_PKCEFromDiscovery(t *testing.T) {
	tests := []struct {
		name     string
		methods  []string
		expected bool
	}{
		{name: "nil", methods: nil, expected: false},
		{name: "empty", methods: []string{}, expected: false},
		{name: "invalid", methods: []string{"invalid"}, expected: false},
		{name: "plain", methods: []string{"plain"}, expected: true},
		{name: "S256", methods: []string{"S256"}, expected: true},
		{name: "both", methods: []string{"plain", "S256"}, expected: true},
		{name: "mixed", methods: []string{"invalid", "S256"}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != oidc.DiscoveryEndpoint {
						w.WriteHeader(http.StatusNotFound)
						return
					}

					if err := json.NewEncoder(w).Encode(map[string]interface{}{
						"issuer":                           "http://" + r.Host,
						"code_challenge_methods_supported": tt.methods,
					}); err != nil {
						t.Fatalf("unexpected error encoding '%v' to JSON: %v", tt.methods, err)
					}
				}))
			defer server.Close()

			t.Log("issuer", server.URL)

			clientID := t.Name() + "-client"
			clientSecret := t.Name() + "-secret"
			targetURL := "http://local-site"
			rp, err := NewRelyingPartyOIDC(
				t.Context(),
				server.URL,
				clientID,
				clientSecret,
				targetURL,
				nil,
				WithPKCEFromDiscovery(nil),
			)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rp == nil {
				t.Fatalf("relying party is nil")
			}

			if rp.IsPKCE() != tt.expected {
				t.Fatalf("expected PKCE to be %v, got %v", tt.expected, rp.IsPKCE())
			}
		})
	}
}

func Test_Oauth2OnlyRPWithPKCEFromDiscovery(t *testing.T) {
	rp, err := NewRelyingPartyOAuth(&oauth2.Config{}, WithPKCEFromDiscovery(nil))

	if !errors.Is(err, ErrInvalidOption) {
		t.Fatal("Oauth2 only RP should return an invalid option error when called with 'WithPKCEFromDiscovery'")
	}

	if !strings.Contains(err.Error(), "PKCE from discovery is not supported for OAuth2 only relying parties") {
		t.Fatal("Wrong error message returned when calling 'WithPKCEFromDiscovery' on an OAuth2 only relying party")
	}

	if rp != nil {
		t.Fatal("RP should be nil when calling 'WithPKCEFromDiscovery' on an OAuth2 only relying party")
	}
}

func Test_CodeExchangeHandler_JWTProfileAudience(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	var assertion string
	var server *httptest.Server
	// The handler runs on the server's goroutine: assert, not require
	// (require calls t.FailNow, which only the test goroutine may call).
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case oidc.DiscoveryEndpoint:
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"jwks_uri":               server.URL + "/keys",
			}))
		case "/token":
			assert.NoError(t, r.ParseForm())
			assertion = r.PostForm.Get("client_assertion")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	rp, err := NewRelyingPartyOIDC(t.Context(), server.URL, "client", "", "http://local-site/callback", nil,
		WithJWTProfile(SignerFromKeyAndKeyID(keyPEM, "key-id")))
	require.NoError(t, err)

	handler := CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp RelyingParty) {
		t.Fatal("callback must not be reached, the token endpoint refuses the code")
	}, rp)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=xyz", nil))

	require.NotEmpty(t, assertion, "code exchange must authenticate with a client assertion")
	var claims oidc.JWTTokenRequest
	_, err = oidc.ParseToken(assertion, &claims)
	require.NoError(t, err)
	// RFC 7523bis: the issuer identifier is the sole audience value; the
	// token endpoint must not appear. Keycloak 26 and Microsoft Entra ID
	// refuse assertions with more than one audience.
	assert.Equal(t, oidc.Audience{server.URL}, claims.Audience)
}

// jwtProfileServer is a discovery document plus token and revocation
// endpoints that record each request and refuse it: the tests are about how
// the client authenticates, not about the response.
type jwtProfileServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
}

func newJWTProfileServer(t *testing.T) *jwtProfileServer {
	t.Helper()
	s := &jwtProfileServer{}
	// The handler runs on the server's goroutine: assert, not require.
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case oidc.DiscoveryEndpoint:
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 s.URL,
				"authorization_endpoint": s.URL + "/authorize",
				"token_endpoint":         s.URL + "/token",
				"revocation_endpoint":    s.URL + "/revoke",
				"jwks_uri":               s.URL + "/keys",
			}))
		case "/token", "/revoke":
			assert.NoError(t, r.ParseForm())
			s.mu.Lock()
			s.requests = append(s.requests, r)
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func testSigner(t *testing.T) Option {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return WithJWTProfile(SignerFromKeyAndKeyID(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "key-id"))
}

// requireJWTProfileAssertion checks that r authenticated with a JWT profile
// assertion only, and returns the assertion's jti.
func requireJWTProfileAssertion(t *testing.T, r *http.Request, issuer string) string {
	t.Helper()
	assert.Equal(t, oidc.ClientAssertionTypeJWTAssertion, r.PostForm.Get("client_assertion_type"))
	_, hasSecret := r.PostForm["client_secret"]
	assert.False(t, hasSecret, "a client_secret parameter next to the assertion is a second authentication method")
	_, _, hasBasic := r.BasicAuth()
	assert.False(t, hasBasic)

	var claims oidc.JWTTokenRequest
	_, err := oidc.ParseToken(r.PostForm.Get("client_assertion"), &claims)
	require.NoError(t, err)
	assert.Equal(t, "client", claims.Issuer)
	assert.Equal(t, "client", claims.Subject)
	assert.Equal(t, oidc.Audience{issuer}, claims.Audience)
	require.NotEmpty(t, claims.JWTID)
	return claims.JWTID
}

func Test_RefreshTokens_JWTProfile(t *testing.T) {
	server := newJWTProfileServer(t)
	rp, err := NewRelyingPartyOIDC(t.Context(), server.URL, "client", "", "http://local-site/callback", nil, testSigner(t))
	require.NoError(t, err)

	for range 2 {
		_, err = RefreshTokens[*oidc.IDTokenClaims](t.Context(), rp, "refresh-token", "", "")
		require.Error(t, err)
	}

	require.Len(t, server.requests, 2)
	jtis := map[string]bool{}
	for _, r := range server.requests {
		assert.Equal(t, "refresh-token", r.PostForm.Get("refresh_token"))
		jtis[requireJWTProfileAssertion(t, r, server.URL)] = true
	}
	assert.Len(t, jtis, 2, "every refresh must sign a new assertion")
}

func Test_RefreshTokens_CallerAssertionWins(t *testing.T) {
	server := newJWTProfileServer(t)
	rp, err := NewRelyingPartyOIDC(t.Context(), server.URL, "client", "", "http://local-site/callback", nil, testSigner(t))
	require.NoError(t, err)

	_, err = RefreshTokens[*oidc.IDTokenClaims](t.Context(), rp, "refresh-token", "caller-assertion", "caller-type")
	require.Error(t, err)

	require.Len(t, server.requests, 1)
	assert.Equal(t, "caller-assertion", server.requests[0].PostForm.Get("client_assertion"))
	assert.Equal(t, "caller-type", server.requests[0].PostForm.Get("client_assertion_type"))
}

func Test_RefreshTokens_ClientSecretWithoutSigner(t *testing.T) {
	server := newJWTProfileServer(t)
	rp, err := NewRelyingPartyOIDC(t.Context(), server.URL, "client", "secret", "http://local-site/callback", nil)
	require.NoError(t, err)

	_, err = RefreshTokens[*oidc.IDTokenClaims](t.Context(), rp, "refresh-token", "", "")
	require.Error(t, err)

	require.Len(t, server.requests, 1)
	assert.Equal(t, "secret", server.requests[0].PostForm.Get("client_secret"))
	assert.Empty(t, server.requests[0].PostForm.Get("client_assertion"))
}

func Test_RefreshTokens_JWTProfileKeepsAuthStyleInHeader(t *testing.T) {
	server := newJWTProfileServer(t)
	rp, err := NewRelyingPartyOIDC(t.Context(), server.URL, "client", "secret", "http://local-site/callback", nil,
		testSigner(t), WithAuthStyle(oauth2.AuthStyleInHeader))
	require.NoError(t, err)

	_, err = RefreshTokens[*oidc.IDTokenClaims](t.Context(), rp, "refresh-token", "", "")
	require.Error(t, err)

	require.Len(t, server.requests, 1)
	user, pass, ok := server.requests[0].BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, "client", user)
	assert.Equal(t, "secret", pass)
	assert.Empty(t, server.requests[0].PostForm.Get("client_assertion"))
}

func Test_RevokeToken_JWTProfile(t *testing.T) {
	server := newJWTProfileServer(t)
	rp, err := NewRelyingPartyOIDC(t.Context(), server.URL, "client", "", "http://local-site/callback", nil, testSigner(t))
	require.NoError(t, err)

	err = RevokeToken(t.Context(), rp, "refresh-token", "refresh_token")
	require.Error(t, err)

	require.Len(t, server.requests, 1)
	assert.Equal(t, "refresh-token", server.requests[0].PostForm.Get("token"))
	assert.Equal(t, "client", server.requests[0].PostForm.Get("client_id"))
	requireJWTProfileAssertion(t, server.requests[0], server.URL)
}

func Test_RevokeToken_ClientSecretWithoutSigner(t *testing.T) {
	server := newJWTProfileServer(t)
	rp, err := NewRelyingPartyOIDC(t.Context(), server.URL, "client", "secret", "http://local-site/callback", nil)
	require.NoError(t, err)

	err = RevokeToken(t.Context(), rp, "refresh-token", "refresh_token")
	require.Error(t, err)

	require.Len(t, server.requests, 1)
	assert.Equal(t, "secret", server.requests[0].PostForm.Get("client_secret"))
	assert.Empty(t, server.requests[0].PostForm.Get("client_assertion"))
}

package rp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	tu "github.com/datasapiens/oidc/v3/internal/testutil"
	"github.com/datasapiens/oidc/v3/pkg/oidc"
)

func Test_verifyTokenResponse(t *testing.T) {
	verifier := &IDTokenVerifier{
		Issuers:           []string{tu.ValidIssuer},
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
			name:       "succes, oauth2 only",
			oauth2Only: true,
			tokens: func() (*oauth2.Token, *oidc.Tokens[*oidc.IDTokenClaims]) {
				accesToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accesToken,
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
				accesToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accesToken,
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
				accesToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accesToken,
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
				accesToken, _ := tu.ValidAccessToken()
				token := &oauth2.Token{
					AccessToken: accesToken,
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

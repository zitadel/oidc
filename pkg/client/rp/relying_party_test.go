package rp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

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

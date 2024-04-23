package rp

import (
	"context"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestVerifyTokens(t *testing.T) {
	verifier := &IDTokenVerifier{
		Issuer:            tu.ValidIssuer,
		MaxAgeIAT:         2 * time.Minute,
		Offset:            time.Second,
		SupportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		KeySet:            tu.KeySet{},
		MaxAge:            2 * time.Minute,
		ACR:               tu.ACRVerify,
		Nonce:             func(context.Context) string { return tu.ValidNonce },
		ClientID:          tu.ValidClientID,
	}
	accessToken, _ := tu.ValidAccessToken()
	atHash, err := oidc.ClaimHash(accessToken, tu.SignatureAlgorithm)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accessToken   string
		idTokenClaims func() (string, *oidc.IDTokenClaims)
		wantErr       bool
	}{
		{
			name:          "without access token",
			idTokenClaims: tu.ValidIDToken,
		},
		{
			name:        "with access token",
			accessToken: accessToken,
			idTokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, atHash,
				)
			},
		},
		{
			name:        "expired id token",
			accessToken: accessToken,
			idTokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration.Add(-time.Hour), tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, atHash,
				)
			},
			wantErr: true,
		},
		{
			name:        "wrong access token",
			accessToken: accessToken,
			idTokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "~~~",
				)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idToken, want := tt.idTokenClaims()
			got, err := VerifyTokens[*oidc.IDTokenClaims](context.Background(), tt.accessToken, idToken, verifier)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, got, want)
		})
	}
}

func TestVerifyIDToken(t *testing.T) {
	verifier := &IDTokenVerifier{
		Issuer:            tu.ValidIssuer,
		MaxAgeIAT:         2 * time.Minute,
		Offset:            time.Second,
		SupportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		KeySet:            tu.KeySet{},
		MaxAge:            2 * time.Minute,
		ACR:               tu.ACRVerify,
		Nonce:             func(context.Context) string { return tu.ValidNonce },
		ClientID:          tu.ValidClientID,
	}

	tests := []struct {
		name           string
		tokenClaims    func() (string, *oidc.IDTokenClaims)
		customVerifier func(verifier *IDTokenVerifier)
		wantErr        bool
	}{
		{
			name:        "success",
			tokenClaims: tu.ValidIDToken,
		},
		{
			name: "custom claims",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDTokenCustom(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
					map[string]any{"some": "thing"},
				)
			},
		},
		{
			name: "skip nonce check",
			customVerifier: func(verifier *IDTokenVerifier) {
				verifier.Nonce = nil
			},
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, "foo",
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
		},
		{
			name:        "parse err",
			tokenClaims: func() (string, *oidc.IDTokenClaims) { return "~~~~", nil },
			wantErr:     true,
		},
		{
			name:        "invalid signature",
			tokenClaims: func() (string, *oidc.IDTokenClaims) { return tu.InvalidSignatureToken, nil },
			wantErr:     true,
		},
		{
			name: "empty subject",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, "", tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
		{
			name: "wrong issuer",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					"foo", tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
		{
			name: "wrong clientID",
			customVerifier: func(verifier *IDTokenVerifier) {
				verifier.ClientID = "foo"
			},
			tokenClaims: tu.ValidIDToken,
			wantErr:     true,
		},
		{
			name: "expired",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration.Add(-time.Hour), tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
		{
			name: "wrong IAT",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, -time.Hour, "",
				)
			},
			wantErr: true,
		},
		{
			name: "wrong acr",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					"else", tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
		{
			name: "expired auth",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime.Add(-time.Hour), tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
		{
			name: "wrong nonce",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return tu.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, "foo",
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, want := tt.tokenClaims()
			if tt.customVerifier != nil {
				tt.customVerifier(verifier)
			}

			got, err := VerifyIDToken[*oidc.IDTokenClaims](context.Background(), token, verifier)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, got, want)
		})
	}
}

func TestVerifyAccessToken(t *testing.T) {
	token, _ := tu.ValidAccessToken()
	hash, err := oidc.ClaimHash(token, tu.SignatureAlgorithm)
	require.NoError(t, err)

	type args struct {
		accessToken  string
		atHash       string
		sigAlgorithm jose.SignatureAlgorithm
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty hash",
		},
		{
			name: "success",
			args: args{
				accessToken:  token,
				atHash:       hash,
				sigAlgorithm: tu.SignatureAlgorithm,
			},
		},
		{
			name: "invalid algorithm",
			args: args{
				accessToken:  token,
				atHash:       hash,
				sigAlgorithm: "foo",
			},
			wantErr: true,
		},
		{
			name: "mismatch",
			args: args{
				accessToken:  token,
				atHash:       "~~",
				sigAlgorithm: tu.SignatureAlgorithm,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAccessToken(tt.args.accessToken, tt.args.atHash, tt.args.sigAlgorithm)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewIDTokenVerifier(t *testing.T) {
	type args struct {
		issuer   string
		clientID string
		keySet   oidc.KeySet
		options  []VerifierOption
	}
	tests := []struct {
		name string
		args args
		want *IDTokenVerifier
	}{
		{
			name: "nil nonce", // otherwise assert.Equal will fail on the function
			args: args{
				issuer:   tu.ValidIssuer,
				clientID: tu.ValidClientID,
				keySet:   tu.KeySet{},
				options: []VerifierOption{
					WithIssuedAtOffset(time.Minute),
					WithIssuedAtMaxAge(time.Hour),
					WithNonce(nil), // otherwise assert.Equal will fail on the function
					WithACRVerifier(nil),
					WithAuthTimeMaxAge(2 * time.Hour),
					WithSupportedSigningAlgorithms("ABC", "DEF"),
				},
			},
			want: &IDTokenVerifier{
				Issuer:            tu.ValidIssuer,
				Offset:            time.Minute,
				MaxAgeIAT:         time.Hour,
				ClientID:          tu.ValidClientID,
				KeySet:            tu.KeySet{},
				Nonce:             nil,
				ACR:               nil,
				MaxAge:            2 * time.Hour,
				SupportedSignAlgs: []string{"ABC", "DEF"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewIDTokenVerifier(tt.args.issuer, tt.args.clientID, tt.args.keySet, tt.args.options...)
			assert.Equal(t, tt.want, got)
		})
	}
}

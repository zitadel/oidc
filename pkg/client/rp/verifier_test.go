package rp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"gopkg.in/square/go-jose.v2"
)

func TestVerifyTokens(t *testing.T) {
	verifier := &idTokenVerifier{
		issuer:            tu.ValidIssuer,
		maxAgeIAT:         2 * time.Minute,
		offset:            time.Second,
		supportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		keySet:            tu.KeySet{},
		maxAge:            2 * time.Minute,
		acr:               tu.ACRVerify,
		nonce:             func(context.Context) string { return tu.ValidNonce },
		clientID:          tu.ValidClientID,
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
	verifier := &idTokenVerifier{
		issuer:            tu.ValidIssuer,
		maxAgeIAT:         2 * time.Minute,
		offset:            time.Second,
		supportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		keySet:            tu.KeySet{},
		maxAge:            2 * time.Minute,
		acr:               tu.ACRVerify,
		nonce:             func(context.Context) string { return tu.ValidNonce },
	}

	tests := []struct {
		name        string
		clientID    string
		tokenClaims func() (string, *oidc.IDTokenClaims)
		wantErr     bool
	}{
		{
			name:        "success",
			clientID:    tu.ValidClientID,
			tokenClaims: tu.ValidIDToken,
		},
		{
			name:        "parse err",
			clientID:    tu.ValidClientID,
			tokenClaims: func() (string, *oidc.IDTokenClaims) { return "~~~~", nil },
			wantErr:     true,
		},
		{
			name:        "invalid signature",
			clientID:    tu.ValidClientID,
			tokenClaims: func() (string, *oidc.IDTokenClaims) { return tu.InvalidSignatureToken, nil },
			wantErr:     true,
		},
		{
			name:     "empty subject",
			clientID: tu.ValidClientID,
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
			name:     "wrong issuer",
			clientID: tu.ValidClientID,
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
			name:        "wrong clientID",
			clientID:    "foo",
			tokenClaims: tu.ValidIDToken,
			wantErr:     true,
		},
		{
			name:     "expired",
			clientID: tu.ValidClientID,
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
			name:     "wrong IAT",
			clientID: tu.ValidClientID,
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
			name:     "wrong acr",
			clientID: tu.ValidClientID,
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
			name:     "expired auth",
			clientID: tu.ValidClientID,
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
			name:     "wrong nonce",
			clientID: tu.ValidClientID,
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
			verifier.clientID = tt.clientID
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
		want IDTokenVerifier
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
			want: &idTokenVerifier{
				issuer:            tu.ValidIssuer,
				offset:            time.Minute,
				maxAgeIAT:         time.Hour,
				clientID:          tu.ValidClientID,
				keySet:            tu.KeySet{},
				nonce:             nil,
				acr:               nil,
				maxAge:            2 * time.Hour,
				supportedSignAlgs: []string{"ABC", "DEF"},
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

package op

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v2/internal/testutil"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"gopkg.in/square/go-jose.v2"
)

func TestNewIDTokenHintVerifier(t *testing.T) {
	keySet := tu.NewKeySet()
	type args struct {
		issuer string
		keySet oidc.KeySet
		opts   []IDTokenHintVerifierOpt
	}
	tests := []struct {
		name string
		args args
		want IDTokenHintVerifier
	}{
		{
			name: "simple",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: keySet,
			},
			want: &idTokenHintVerifier{
				issuer: tu.ValidIssuer,
				keySet: keySet,
			},
		},
		{
			name: "with signature algorithm",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: keySet,
				opts: []IDTokenHintVerifierOpt{
					WithSupportedIDTokenHintSigningAlgorithms("ABC", "DEF"),
				},
			},
			want: &idTokenHintVerifier{
				issuer:            tu.ValidIssuer,
				keySet:            keySet,
				supportedSignAlgs: []string{"ABC", "DEF"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewIDTokenHintVerifier(tt.args.issuer, tt.args.keySet, tt.args.opts...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifyIDTokenHint(t *testing.T) {
	keySet := tu.NewKeySet()
	verifier := &idTokenHintVerifier{
		issuer:            tu.ValidIssuer,
		maxAgeIAT:         2 * time.Minute,
		offset:            time.Second,
		supportedSignAlgs: []string{string(jose.PS512)},
		maxAge:            2 * time.Minute,
		acr:               tu.ACRVerify,
		keySet:            keySet,
	}

	tests := []struct {
		name        string
		tokenClaims func() (string, *oidc.IDTokenClaims)
		wantErr     bool
	}{
		{
			name:        "success",
			tokenClaims: keySet.ValidIDToken,
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
			name: "wrong issuer",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return keySet.NewIDToken(
					"foo", tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime, tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
		{
			name: "expired",
			tokenClaims: func() (string, *oidc.IDTokenClaims) {
				return keySet.NewIDToken(
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
				return keySet.NewIDToken(
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
				return keySet.NewIDToken(
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
				return keySet.NewIDToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidAuthTime.Add(-time.Hour), tu.ValidNonce,
					tu.ValidACR, tu.ValidAMR, tu.ValidClientID, tu.ValidSkew, "",
				)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, want := tt.tokenClaims()

			got, err := VerifyIDTokenHint[*oidc.IDTokenClaims](context.Background(), token, verifier)
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

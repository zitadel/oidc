package op

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestNewAccessTokenVerifier(t *testing.T) {
	type args struct {
		issuer string
		keySet oidc.KeySet
		opts   []AccessTokenVerifierOpt
	}
	tests := []struct {
		name string
		args args
		want *AccessTokenVerifier
	}{
		{
			name: "simple",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
			},
			want: &AccessTokenVerifier{
				Issuer: tu.ValidIssuer,
				KeySet: tu.KeySet{},
			},
		},
		{
			name: "with signature algorithm",
			args: args{
				issuer: tu.ValidIssuer,
				keySet: tu.KeySet{},
				opts: []AccessTokenVerifierOpt{
					WithSupportedAccessTokenSigningAlgorithms("ABC", "DEF"),
				},
			},
			want: &AccessTokenVerifier{
				Issuer:            tu.ValidIssuer,
				KeySet:            tu.KeySet{},
				SupportedSignAlgs: []string{"ABC", "DEF"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAccessTokenVerifier(tt.args.issuer, tt.args.keySet, tt.args.opts...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifyAccessToken(t *testing.T) {
	verifier := &AccessTokenVerifier{
		Issuer:            tu.ValidIssuer,
		MaxAgeIAT:         2 * time.Minute,
		Offset:            time.Second,
		SupportedSignAlgs: []string{string(tu.SignatureAlgorithm)},
		KeySet:            tu.KeySet{},
	}

	tests := []struct {
		name        string
		tokenClaims func() (string, *oidc.AccessTokenClaims)
		wantErr     bool
	}{
		{
			name:        "success",
			tokenClaims: tu.ValidAccessToken,
		},
		{
			name:        "parse err",
			tokenClaims: func() (string, *oidc.AccessTokenClaims) { return "~~~~", nil },
			wantErr:     true,
		},
		{
			name:        "invalid signature",
			tokenClaims: func() (string, *oidc.AccessTokenClaims) { return tu.InvalidSignatureToken, nil },
			wantErr:     true,
		},
		{
			name: "wrong issuer",
			tokenClaims: func() (string, *oidc.AccessTokenClaims) {
				return tu.NewAccessToken(
					"foo", tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration, tu.ValidJWTID, tu.ValidClientID,
					tu.ValidSkew,
				)
			},
			wantErr: true,
		},
		{
			name: "expired",
			tokenClaims: func() (string, *oidc.AccessTokenClaims) {
				return tu.NewAccessToken(
					tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
					tu.ValidExpiration.Add(-time.Hour), tu.ValidJWTID, tu.ValidClientID,
					tu.ValidSkew,
				)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, want := tt.tokenClaims()

			got, err := VerifyAccessToken[*oidc.AccessTokenClaims](context.Background(), token, verifier)
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

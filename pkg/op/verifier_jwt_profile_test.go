package op_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestNewJWTProfileVerifier(t *testing.T) {
	want := &op.JWTProfileVerifier{
		Verifier: oidc.Verifier{
			Issuer:    tu.ValidIssuer,
			MaxAgeIAT: time.Minute,
			Offset:    time.Second,
		},
		Storage: tu.JWTProfileKeyStorage{},
	}
	got := op.NewJWTProfileVerifier(tu.JWTProfileKeyStorage{}, tu.ValidIssuer, time.Minute, time.Second, op.SubjectCheck(func(request *oidc.JWTTokenRequest) error {
		return oidc.ErrSubjectMissing
	}))
	assert.Equal(t, want.Verifier, got.Verifier)
	assert.Equal(t, want.Storage, got.Storage)
	assert.ErrorIs(t, got.CheckSubject(nil), oidc.ErrSubjectMissing)
}

func TestVerifyJWTAssertion(t *testing.T) {
	errCtx, cancel := context.WithCancel(context.Background())
	cancel()

	verifier := op.NewJWTProfileVerifier(tu.JWTProfileKeyStorage{}, tu.ValidIssuer, time.Minute, 0)
	tests := []struct {
		name     string
		ctx      context.Context
		newToken func() (string, *oidc.JWTTokenRequest)
		wantErr  bool
	}{
		{
			name:     "parse error",
			ctx:      context.Background(),
			newToken: func() (string, *oidc.JWTTokenRequest) { return "!", nil },
			wantErr:  true,
		},
		{
			name: "wrong audience",
			ctx:  context.Background(),
			newToken: func() (string, *oidc.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, tu.ValidClientID, []string{"wrong"},
					time.Now(), tu.ValidExpiration,
				)
			},
			wantErr: true,
		},
		{
			name: "expired",
			ctx:  context.Background(),
			newToken: func() (string, *oidc.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, tu.ValidClientID, []string{tu.ValidIssuer},
					time.Now(), time.Now().Add(-time.Hour),
				)
			},
			wantErr: true,
		},
		{
			name: "invalid iat",
			ctx:  context.Background(),
			newToken: func() (string, *oidc.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, tu.ValidClientID, []string{tu.ValidIssuer},
					time.Now().Add(time.Hour), tu.ValidExpiration,
				)
			},
			wantErr: true,
		},
		{
			name: "invalid subject",
			ctx:  context.Background(),
			newToken: func() (string, *oidc.JWTTokenRequest) {
				return tu.NewJWTProfileAssertion(
					tu.ValidClientID, "wrong", []string{tu.ValidIssuer},
					time.Now(), tu.ValidExpiration,
				)
			},
			wantErr: true,
		},
		{
			name:     "check signature fail",
			ctx:      errCtx,
			newToken: tu.ValidJWTProfileAssertion,
			wantErr:  true,
		},
		{
			name:     "ok",
			ctx:      context.Background(),
			newToken: tu.ValidJWTProfileAssertion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertion, want := tt.newToken()
			got, err := op.VerifyJWTAssertion(tt.ctx, assertion, verifier)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

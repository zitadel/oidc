package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptToken(t *testing.T) {
	const tokenString = "ABC"
	got, err := DecryptToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, tokenString, got)
}

func TestDefaultACRVerifier(t *testing.T) {
	acrVerfier := DefaultACRVerifier([]string{"foo", "bar"})

	tests := []struct {
		name    string
		acr     string
		wantErr string
	}{
		{
			name: "ok",
			acr:  "bar",
		},
		{
			name:    "error",
			acr:     "hello",
			wantErr: "expected one of: [foo bar], got: \"hello\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := acrVerfier(tt.acr)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCheckSubject(t *testing.T) {
	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &TokenClaims{},
			wantErr: ErrSubjectMissing,
		},
		{
			name: "ok",
			claims: &TokenClaims{
				Subject: "foo",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSubject(tt.claims)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckIssuer(t *testing.T) {
	const issuer = "foo.bar"
	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &TokenClaims{},
			wantErr: ErrIssuerInvalid,
		},
		{
			name: "wrong",
			claims: &TokenClaims{
				Issuer: "wrong",
			},
			wantErr: ErrIssuerInvalid,
		},
		{
			name: "ok",
			claims: &TokenClaims{
				Issuer: issuer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckIssuer(tt.claims, issuer)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAudience(t *testing.T) {
	const clientID = "foo.bar"
	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &TokenClaims{},
			wantErr: ErrAudience,
		},
		{
			name: "wrong",
			claims: &TokenClaims{
				Audience: []string{"wrong"},
			},
			wantErr: ErrAudience,
		},
		{
			name: "ok",
			claims: &TokenClaims{
				Audience: []string{clientID},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckAudience(tt.claims, clientID)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAuthorizedParty(t *testing.T) {
	const clientID = "foo.bar"
	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name: "single audience, no azp",
			claims: &TokenClaims{
				Audience: []string{clientID},
			},
		},
		{
			name: "multiple audience, no azp",
			claims: &TokenClaims{
				Audience: []string{clientID, "other"},
			},
			wantErr: ErrAzpMissing,
		},
		{
			name: "single audience, with azp",
			claims: &TokenClaims{
				Audience:        []string{clientID},
				AuthorizedParty: clientID,
			},
		},
		{
			name: "multiple audience, with azp",
			claims: &TokenClaims{
				Audience:        []string{clientID, "other"},
				AuthorizedParty: clientID,
			},
		},
		{
			name: "wrong azp",
			claims: &TokenClaims{
				AuthorizedParty: "wrong",
			},
			wantErr: ErrAzpInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckAuthorizedParty(tt.claims, clientID)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckExpiration(t *testing.T) {
	const offset = time.Minute
	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &TokenClaims{},
			wantErr: ErrExpired,
		},
		{
			name: "expired",
			claims: &TokenClaims{
				Expiration: FromTime(time.Now().Add(-2 * offset)),
			},
			wantErr: ErrExpired,
		},
		{
			name: "valid",
			claims: &TokenClaims{
				Expiration: FromTime(time.Now().Add(2 * offset)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckExpiration(tt.claims, offset)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckIssuedAt(t *testing.T) {
	const offset = time.Minute
	tests := []struct {
		name      string
		maxAgeIAT time.Duration
		claims    Claims
		wantErr   error
	}{
		{
			name:    "missing",
			claims:  &TokenClaims{},
			wantErr: ErrIatMissing,
		},
		{
			name: "future",
			claims: &TokenClaims{
				IssuedAt: FromTime(time.Now().Add(time.Hour)),
			},
			wantErr: ErrIatInFuture,
		},
		{
			name: "no max",
			claims: &TokenClaims{
				IssuedAt: FromTime(time.Now()),
			},
		},
		{
			name:      "past max",
			maxAgeIAT: time.Minute,
			claims: &TokenClaims{
				IssuedAt: FromTime(time.Now().Add(-time.Hour)),
			},
			wantErr: ErrIatToOld,
		},
		{
			name:      "within max",
			maxAgeIAT: time.Hour,
			claims: &TokenClaims{
				IssuedAt: FromTime(time.Now()),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckIssuedAt(tt.claims, tt.maxAgeIAT, offset)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckNonce(t *testing.T) {
	const nonce = "123"
	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name:    "missing",
			claims:  &TokenClaims{},
			wantErr: ErrNonceInvalid,
		},
		{
			name: "wrong",
			claims: &TokenClaims{
				Nonce: "wrong",
			},
			wantErr: ErrNonceInvalid,
		},
		{
			name: "ok",
			claims: &TokenClaims{
				Nonce: nonce,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckNonce(tt.claims, nonce)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAuthorizationContextClassReference(t *testing.T) {
	tests := []struct {
		name    string
		acr     ACRVerifier
		wantErr error
	}{
		{
			name:    "error",
			acr:     func(s string) error { return errors.New("oops") },
			wantErr: ErrAcrInvalid,
		},
		{
			name: "ok",
			acr:  func(s string) error { return nil },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckAuthorizationContextClassReference(&IDTokenClaims{}, tt.acr)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCheckAuthTime(t *testing.T) {
	tests := []struct {
		name    string
		claims  Claims
		maxAge  time.Duration
		wantErr error
	}{
		{
			name:   "no max age",
			claims: &TokenClaims{},
		},
		{
			name:    "missing",
			claims:  &TokenClaims{},
			maxAge:  time.Minute,
			wantErr: ErrAuthTimeNotPresent,
		},
		{
			name:   "expired",
			maxAge: time.Minute,
			claims: &TokenClaims{
				AuthTime: FromTime(time.Now().Add(-time.Hour)),
			},
			wantErr: ErrAuthTimeToOld,
		},
		{
			name:   "ok",
			maxAge: time.Minute,
			claims: &TokenClaims{
				AuthTime: NowTime(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckAuthTime(tt.claims, tt.maxAge)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

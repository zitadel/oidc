package oidc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaPublicKeyOfBits builds a public key of an exact size, avoiding slow keygen.
func rsaPublicKeyOfBits(bits int) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
}

func TestValidDPoPJKT(t *testing.T) {
	valid := CodeHash("some-authorization-code")
	require.Len(t, valid, 43)

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "valid thumbprint", value: valid, want: true},
		{name: "empty", value: "", want: false},
		{name: "too short", value: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), want: false},
		{name: "too long", value: base64.RawURLEncoding.EncodeToString(make([]byte, 48)), want: false},
		{name: "padded", value: base64.URLEncoding.EncodeToString(make([]byte, 32)), want: false},
		{name: "not base64url", value: "!!!not-base64!!!", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ValidDPoPJKT(tt.value))
		})
	}
}

func TestCodeHash(t *testing.T) {
	tests := []string{"", "authcode", "device-code-1234"}
	for _, code := range tests {
		t.Run(code, func(t *testing.T) {
			got := CodeHash(code)
			sum := sha256.Sum256([]byte(code))
			assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), got)
			assert.True(t, ValidDPoPJKT(got))
		})
	}
	assert.NotEqual(t, CodeHash("a"), CodeHash("b"))
}

func TestJWKThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := &jose.JSONWebKey{Key: key.Public()}

	got, err := JWKThumbprint(jwk)
	require.NoError(t, err)
	assert.True(t, ValidDPoPJKT(got), "thumbprint should be a valid dpop_jkt")

	// Deterministic and independent of JWK metadata.
	withMeta := &jose.JSONWebKey{Key: key.Public(), KeyID: "kid", Use: "sig", Algorithm: "ES256"}
	again, err := JWKThumbprint(withMeta)
	require.NoError(t, err)
	assert.Equal(t, got, again)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherTP, err := JWKThumbprint(&jose.JSONWebKey{Key: other.Public()})
	require.NoError(t, err)
	assert.NotEqual(t, got, otherTP)
}

func TestCanonicalJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := &jose.JSONWebKey{Key: key.Public(), KeyID: "kid", Use: "sig", Algorithm: "ES256"}

	canonical, err := CanonicalJWK(jwk)
	require.NoError(t, err)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(canonical, &fields))
	assert.Contains(t, fields, "kty")
	assert.NotContains(t, fields, "kid")
	assert.NotContains(t, fields, "use")
	assert.NotContains(t, fields, "alg")

	// The stripped key still identifies the same key.
	full, err := JWKThumbprint(jwk)
	require.NoError(t, err)
	var parsed jose.JSONWebKey
	require.NoError(t, parsed.UnmarshalJSON(canonical))
	stripped, err := JWKThumbprint(&parsed)
	require.NoError(t, err)
	assert.Equal(t, full, stripped)
}

func TestValidateDPoPKeyStrength(t *testing.T) {
	ecKey := func(c elliptic.Curve) *ecdsa.PublicKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		require.NoError(t, err)
		return &k.PublicKey
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     any
		wantErr bool
	}{
		{name: "RSA 2048", key: rsaPublicKeyOfBits(2048)},
		{name: "RSA 8192", key: rsaPublicKeyOfBits(8192)},
		{name: "RSA 1024 too small", key: rsaPublicKeyOfBits(1024), wantErr: true},
		{name: "RSA 9216 too large", key: rsaPublicKeyOfBits(9216), wantErr: true},
		{name: "EC P-256", key: ecKey(elliptic.P256())},
		{name: "EC P-384", key: ecKey(elliptic.P384())},
		{name: "EC P-521", key: ecKey(elliptic.P521())},
		{name: "EC P-224 not allowed", key: ecKey(elliptic.P224()), wantErr: true},
		{name: "ed25519", key: edPub},
		{name: "unrestricted other type", key: "not a key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDPoPKeyStrength(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDPoPProofClaims_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    DPoPProofClaims
		wantErr bool
	}{
		{
			name: "valid",
			json: `{"jti":"id-1","htm":"POST","htu":"https://op.example.com/token","iat":1700000000,"c_s256":"abc"}`,
			want: DPoPProofClaims{JWTID: "id-1", HTTPMethod: "POST", HTTPURI: "https://op.example.com/token", IssuedAt: 1700000000, CodeHash: "abc"},
		},
		{
			name: "missing iat",
			json: `{"jti":"id-2","htm":"POST","htu":"https://op.example.com/token"}`,
			want: DPoPProofClaims{JWTID: "id-2", HTTPMethod: "POST", HTTPURI: "https://op.example.com/token"},
		},
		{name: "null iat", json: `{"iat":null}`, wantErr: true},
		{name: "iat wrong type", json: `{"iat":"soon"}`, wantErr: true},
		{name: "invalid json", json: `{`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DPoPProofClaims
			err := json.Unmarshal([]byte(tt.json), &got)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

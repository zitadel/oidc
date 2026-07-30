package rp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type wrappedCryptoSigner struct {
	crypto.Signer
}

func TestWithKeyBinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	configured := &relyingParty{oauthConfig: &oauth2.Config{Scopes: []string{oidc.ScopeOpenID}}}
	require.NoError(t, WithKeyBinding(&wrappedCryptoSigner{Signer: key}, jose.ES256)(configured))
	require.NotNil(t, configured.keyBinding)
	assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, configured.oauthConfig.Scopes)

	require.NoError(t, WithKeyBinding(key, jose.ES256)(configured))
	assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, configured.oauthConfig.Scopes)
}

// TestWithKeyBindingDoesNotAliasCallerScopes ensures the caller's scope slice
// is never mutated in place when bound_key is appended.
func TestWithKeyBindingDoesNotAliasCallerScopes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	callerScopes := make([]string, 1, 4) // spare capacity, so append would alias
	callerScopes[0] = oidc.ScopeOpenID
	configured := &relyingParty{oauthConfig: &oauth2.Config{Scopes: callerScopes}}
	require.NoError(t, WithKeyBinding(key, jose.ES256)(configured))

	assert.Equal(t, []string{oidc.ScopeOpenID}, callerScopes)
	assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, configured.oauthConfig.Scopes)
}

func TestWithKeyBindingRejectsInvalidConfiguration(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var nilKey *ecdsa.PrivateKey

	tests := []struct {
		name   string
		rp     *relyingParty
		signer crypto.Signer
		alg    jose.SignatureAlgorithm
		want   error
	}{
		{name: "oauth only", rp: &relyingParty{oauth2Only: true, oauthConfig: &oauth2.Config{}}, signer: key, alg: jose.ES256, want: ErrInvalidOption},
		{name: "nil signer", rp: &relyingParty{oauthConfig: &oauth2.Config{}}, alg: jose.ES256, want: ErrInvalidKeyBinding},
		{name: "typed nil signer", rp: &relyingParty{oauthConfig: &oauth2.Config{}}, signer: nilKey, alg: jose.ES256, want: ErrInvalidKeyBinding},
		{name: "symmetric algorithm", rp: &relyingParty{oauthConfig: &oauth2.Config{}}, signer: key, alg: jose.HS256, want: ErrInvalidKeyBinding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WithKeyBinding(tt.signer, tt.alg)(tt.rp)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestKeyBindingProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	configured := &relyingParty{oauthConfig: &oauth2.Config{}}
	require.NoError(t, WithKeyBinding(&wrappedCryptoSigner{Signer: key}, jose.ES256)(configured))

	const endpoint = "https://issuer.example.com/oauth/token"
	const code = "code"
	compact, err := configured.keyBinding.proof(http.MethodPost, endpoint, code)
	require.NoError(t, err)
	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Len(t, signed.Signatures, 1)
	assert.Equal(t, string(oidc.DPoPProofType), signed.Signatures[0].Header.ExtraHeaders[jose.HeaderType])
	require.NotNil(t, signed.Signatures[0].Header.JSONWebKey)
	assert.Equal(t, string(jose.ES256), signed.Signatures[0].Header.JSONWebKey.Algorithm)
	payload, err := signed.Verify(&key.PublicKey)
	require.NoError(t, err)
	var claims oidc.DPoPProofClaims
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.NotEmpty(t, claims.JWTID)
	assert.Equal(t, http.MethodPost, claims.HTTPMethod)
	assert.Equal(t, endpoint, claims.HTTPURI)
	assert.Equal(t, oidc.CodeHash(code), claims.CodeHash)
}

func TestKeyBindingProofPSSUsesHashLengthSalt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	configured := &relyingParty{oauthConfig: &oauth2.Config{}}
	require.NoError(t, WithKeyBinding(&wrappedCryptoSigner{Signer: key}, jose.PS256)(configured))

	compact, err := configured.keyBinding.proof(http.MethodPost, "https://issuer.example.com/oauth/token", "code")
	require.NoError(t, err)
	parts := strings.Split(compact, ".")
	require.Len(t, parts, 3)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	assert.NoError(t, rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}))
}

func TestVerifyKeyBindingIDToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk, err := oidc.CanonicalJWK(&jose.JSONWebKey{Key: &key.PublicKey})
	require.NoError(t, err)
	jkt, err := oidc.JWKThumbprint(&jose.JSONWebKey{Key: &key.PublicKey})
	require.NoError(t, err)
	payload, err := json.Marshal(struct {
		Confirmation *oidc.Confirmation `json:"cnf"`
	}{Confirmation: &oidc.Confirmation{JWK: jwk}})
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		new(jose.SignerOptions).WithType(oidc.IDTokenTypeDPoP),
	)
	require.NoError(t, err)
	signed, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := signed.CompactSerialize()
	require.NoError(t, err)

	assert.NoError(t, verifyKeyBindingIDToken(compact, jose.ES256, jkt))
	assert.ErrorIs(t, verifyKeyBindingIDToken(compact, jose.ES256, "wrong"), ErrKeyBindingConfirmation)

	privateJWK, err := json.Marshal(jose.JSONWebKey{Key: key})
	require.NoError(t, err)
	privatePayload, err := json.Marshal(struct {
		Confirmation *oidc.Confirmation `json:"cnf"`
	}{Confirmation: &oidc.Confirmation{JWK: privateJWK}})
	require.NoError(t, err)
	privateSigned, err := signer.Sign(privatePayload)
	require.NoError(t, err)
	privateCompact, err := privateSigned.CompactSerialize()
	require.NoError(t, err)
	assert.ErrorIs(t, verifyKeyBindingIDToken(privateCompact, jose.ES256, jkt), ErrKeyBindingIDToken)
}

// TestWithKeyBindingRejectsWeakKeys ensures the RP rejects a binding key the OP
// would reject when verifying the proof, so misconfiguration surfaces at setup
// instead of after the user has completed the authorization.
func TestWithKeyBindingRejectsWeakKeys(t *testing.T) {
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	configured := &relyingParty{oauthConfig: &oauth2.Config{Scopes: []string{oidc.ScopeOpenID}}}
	err = WithKeyBinding(weakRSA, jose.RS256)(configured)
	require.ErrorIs(t, err, ErrInvalidKeyBinding)
	assert.Nil(t, configured.keyBinding)

	strongRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	assert.NoError(t, WithKeyBinding(strongRSA, jose.RS256)(configured))
}

// TestKeyBindingTransportRefusesForeignURL ensures a proof is only ever signed
// for the configured token endpoint, so a token-endpoint redirect cannot harvest
// the authorization code together with a valid proof over it.
func TestKeyBindingTransportRefusesForeignURL(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	configured := &relyingParty{oauthConfig: &oauth2.Config{Scopes: []string{oidc.ScopeOpenID}}}
	require.NoError(t, WithKeyBinding(key, jose.ES256)(configured))

	const tokenEndpoint = "https://op.example.com/token"
	client := keyBindingHTTPClient(nil, configured, "thecode", tokenEndpoint)
	transport := client.Transport

	req, err := http.NewRequest(http.MethodPost, "https://evil.example.com/token", nil)
	require.NoError(t, err)
	_, err = transport.RoundTrip(req)
	require.ErrorIs(t, err, ErrInvalidKeyBinding)
	assert.Empty(t, req.Header.Get(oidc.DPoPHeader))

	// Redirects must be refused rather than re-POSTing the code elsewhere.
	require.NotNil(t, client.CheckRedirect)
	redirect, err := http.NewRequest(http.MethodPost, "https://evil.example.com/", nil)
	require.NoError(t, err)
	assert.ErrorIs(t, client.CheckRedirect(redirect, nil), ErrInvalidKeyBinding)
}

package rp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func mustECKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(c, rand.Reader)
	require.NoError(t, err)
	return key
}

func newKeyBoundRP(t *testing.T) *relyingParty {
	t.Helper()
	rp := &relyingParty{oauthConfig: &oauth2.Config{Scopes: []string{"openid"}}}
	require.NoError(t, WithKeyBinding(mustECKey(t, elliptic.P256()), jose.ES256)(rp))
	return rp
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestKeyBindingAlgMatchesKey(t *testing.T) {
	rsaPub := &mustRSAKey(t, 2048).PublicKey
	ecP256 := &mustECKey(t, elliptic.P256()).PublicKey
	ecP384 := &mustECKey(t, elliptic.P384()).PublicKey
	ecP521 := &mustECKey(t, elliptic.P521()).PublicKey
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name string
		alg  jose.SignatureAlgorithm
		pub  crypto.PublicKey
		want bool
	}{
		{name: "RSA with RS256", alg: jose.RS256, pub: rsaPub, want: true},
		{name: "RSA with PS512", alg: jose.PS512, pub: rsaPub, want: true},
		{name: "RSA with ES256", alg: jose.ES256, pub: rsaPub, want: false},
		{name: "RSA with HS256", alg: jose.HS256, pub: rsaPub, want: false},
		{name: "P-256 with ES256", alg: jose.ES256, pub: ecP256, want: true},
		{name: "P-256 with ES384", alg: jose.ES384, pub: ecP256, want: false},
		{name: "P-384 with ES384", alg: jose.ES384, pub: ecP384, want: true},
		{name: "P-521 with ES512", alg: jose.ES512, pub: ecP521, want: true},
		{name: "P-256 with RS256", alg: jose.RS256, pub: ecP256, want: false},
		{name: "ed25519 with EdDSA", alg: jose.EdDSA, pub: edPub, want: true},
		{name: "ed25519 with ES256", alg: jose.ES256, pub: edPub, want: false},
		{name: "opaque key asymmetric alg", alg: jose.ES256, pub: "opaque", want: true},
		{name: "opaque key symmetric alg", alg: jose.HS256, pub: "opaque", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, keyBindingAlgMatchesKey(tt.alg, tt.pub))
		})
	}
}

func mustRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return key
}

func TestNilCryptoSigner(t *testing.T) {
	var typedNil *rsa.PrivateKey
	assert.True(t, nilCryptoSigner(nil))
	assert.True(t, nilCryptoSigner(typedNil))
	assert.False(t, nilCryptoSigner(mustECKey(t, elliptic.P256())))
}

func TestWithKeyBinding(t *testing.T) {
	t.Run("oauth2 only", func(t *testing.T) {
		rp := &relyingParty{oauth2Only: true, oauthConfig: &oauth2.Config{}}
		err := WithKeyBinding(mustECKey(t, elliptic.P256()), jose.ES256)(rp)
		assert.ErrorIs(t, err, ErrInvalidOption)
	})

	t.Run("nil signer", func(t *testing.T) {
		rp := &relyingParty{oauthConfig: &oauth2.Config{}}
		err := WithKeyBinding(nil, jose.ES256)(rp)
		assert.ErrorIs(t, err, ErrInvalidKeyBinding)
	})

	t.Run("alg does not match key", func(t *testing.T) {
		rp := &relyingParty{oauthConfig: &oauth2.Config{}}
		err := WithKeyBinding(mustECKey(t, elliptic.P256()), jose.RS256)(rp)
		assert.ErrorIs(t, err, ErrInvalidKeyBinding)
	})

	t.Run("key too weak", func(t *testing.T) {
		rp := &relyingParty{oauthConfig: &oauth2.Config{}}
		err := WithKeyBinding(mustRSAKey(t, 1024), jose.RS256)(rp)
		assert.ErrorIs(t, err, ErrInvalidKeyBinding)
	})

	t.Run("success adds scope and thumbprint", func(t *testing.T) {
		key := mustECKey(t, elliptic.P256())
		rp := &relyingParty{oauthConfig: &oauth2.Config{Scopes: []string{"openid"}}}
		require.NoError(t, WithKeyBinding(key, jose.ES256)(rp))

		require.NotNil(t, rp.keyBinding)
		want, err := oidc.JWKThumbprint(&jose.JSONWebKey{Key: key.Public(), Algorithm: string(jose.ES256)})
		require.NoError(t, err)
		assert.Equal(t, want, rp.KeyBindingThumbprint())
		assert.Contains(t, rp.oauthConfig.Scopes, oidc.ScopeBoundKey)
		assert.Contains(t, rp.oauthConfig.Scopes, "openid")
	})

	t.Run("does not duplicate scope", func(t *testing.T) {
		rp := &relyingParty{oauthConfig: &oauth2.Config{Scopes: []string{"openid", oidc.ScopeBoundKey}}}
		require.NoError(t, WithKeyBinding(mustECKey(t, elliptic.P256()), jose.ES256)(rp))

		var count int
		for _, s := range rp.oauthConfig.Scopes {
			if s == oidc.ScopeBoundKey {
				count++
			}
		}
		assert.Equal(t, 1, count)
	})
}

func TestKeyBindingRP(t *testing.T) {
	_, ok := keyBindingRP(&relyingParty{})
	assert.False(t, ok)

	configured, ok := keyBindingRP(newKeyBoundRP(t))
	assert.True(t, ok)
	assert.NotEmpty(t, configured.KeyBindingThumbprint())
}

func TestSignDPoPProof(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		_, err := (&relyingParty{}).SignDPoPProof("POST", "https://op.example.com/token", "code")
		assert.ErrorIs(t, err, ErrInvalidKeyBinding)
	})

	tests := []struct {
		name string
		code string
	}{
		{name: "with code", code: "authorization-code"},
		{name: "without code", code: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := newKeyBoundRP(t)
			const htu = "https://op.example.com/token"
			proof, err := rp.SignDPoPProof(http.MethodPost, htu, tt.code)
			require.NoError(t, err)

			jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
			require.NoError(t, err)
			require.Len(t, jws.Signatures, 1)

			typ := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType]
			assert.Equal(t, string(oidc.DPoPProofType), typ)
			require.NotNil(t, jws.Signatures[0].Header.JSONWebKey, "proof must embed the public jwk")
			assert.True(t, jws.Signatures[0].Header.JSONWebKey.IsPublic())

			var claims oidc.DPoPProofClaims
			require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
			assert.Equal(t, http.MethodPost, claims.HTTPMethod)
			assert.Equal(t, htu, claims.HTTPURI)
			assert.NotEmpty(t, claims.JWTID)
			if tt.code == "" {
				assert.Empty(t, claims.CodeHash)
			} else {
				assert.Equal(t, oidc.CodeHash(tt.code), claims.CodeHash)
			}
		})
	}
}

func signKeyBoundIDToken(t *testing.T, opKey crypto.Signer, typ string, cnfKey crypto.PublicKey) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: opKey},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	require.NoError(t, err)

	payload := map[string]any{"sub": "user-1"}
	if cnfKey != nil {
		jwkBytes, err := (&jose.JSONWebKey{Key: cnfKey}).MarshalJSON()
		require.NoError(t, err)
		payload["cnf"] = map[string]json.RawMessage{"jwk": jwkBytes}
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	jws, err := signer.Sign(raw)
	require.NoError(t, err)
	token, err := jws.CompactSerialize()
	require.NoError(t, err)
	return token
}

func TestVerifyKeyBindingIDToken(t *testing.T) {
	opKey := mustECKey(t, elliptic.P256())
	boundKey := mustECKey(t, elliptic.P256())
	otherKey := mustECKey(t, elliptic.P256())

	expectedJKT, err := oidc.JWKThumbprint(&jose.JSONWebKey{Key: boundKey.Public()})
	require.NoError(t, err)

	tests := []struct {
		name    string
		token   string
		alg     jose.SignatureAlgorithm
		wantErr error
	}{
		{
			name:  "valid",
			token: signKeyBoundIDToken(t, opKey, string(oidc.IDTokenTypeDPoP), boundKey.Public()),
			alg:   jose.ES256,
		},
		{
			name:    "wrong typ",
			token:   signKeyBoundIDToken(t, opKey, "JWT", boundKey.Public()),
			alg:     jose.ES256,
			wantErr: ErrKeyBindingIDToken,
		},
		{
			name:    "missing cnf",
			token:   signKeyBoundIDToken(t, opKey, string(oidc.IDTokenTypeDPoP), nil),
			alg:     jose.ES256,
			wantErr: ErrKeyBindingIDToken,
		},
		{
			name:    "cnf key mismatch",
			token:   signKeyBoundIDToken(t, opKey, string(oidc.IDTokenTypeDPoP), otherKey.Public()),
			alg:     jose.ES256,
			wantErr: ErrKeyBindingConfirmation,
		},
		{
			name:    "unparseable token",
			token:   "not-a-jwt",
			alg:     jose.ES256,
			wantErr: ErrKeyBindingIDToken,
		},
		{
			name:    "alg mismatch",
			token:   signKeyBoundIDToken(t, opKey, string(oidc.IDTokenTypeDPoP), boundKey.Public()),
			alg:     jose.ES384,
			wantErr: ErrKeyBindingIDToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyKeyBindingIDToken(tt.token, tt.alg, expectedJKT)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestHTU(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantClaim string
		wantKey   string
	}{
		{name: "plain", raw: "https://op.example.com/token",
			wantClaim: "https://op.example.com/token", wantKey: "https://op.example.com/token"},
		{name: "strips query", raw: "https://op.example.com/token?tenant=42",
			wantClaim: "https://op.example.com/token", wantKey: "https://op.example.com/token"},
		{name: "strips empty query", raw: "https://op.example.com/token?",
			wantClaim: "https://op.example.com/token", wantKey: "https://op.example.com/token"},
		{name: "strips fragment", raw: "https://op.example.com/token#frag",
			wantClaim: "https://op.example.com/token", wantKey: "https://op.example.com/token"},
		{name: "strips userinfo", raw: "https://user:secret@op.example.com/token",
			wantClaim: "https://op.example.com/token", wantKey: "https://op.example.com/token"},
		// The claim keeps the spelling the OP published; only the key normalizes.
		{name: "keeps host case in the claim", raw: "https://OP.Example.COM/token",
			wantClaim: "https://OP.Example.COM/token", wantKey: "https://op.example.com/token"},
		{name: "keeps default https port in the claim", raw: "https://op.example.com:443/token",
			wantClaim: "https://op.example.com:443/token", wantKey: "https://op.example.com/token"},
		{name: "keeps default http port in the claim", raw: "http://op.example.com:80/token",
			wantClaim: "http://op.example.com:80/token", wantKey: "http://op.example.com/token"},
		{name: "keeps non-default port", raw: "https://op.example.com:8443/token",
			wantClaim: "https://op.example.com:8443/token", wantKey: "https://op.example.com:8443/token"},
		{name: "ipv6 literal uppercased", raw: "https://[2001:DB8::1]/token",
			wantClaim: "https://[2001:DB8::1]/token", wantKey: "https://[2001:db8::1]/token"},
		{name: "keeps ipv6 brackets when default port", raw: "https://[2001:db8::1]:443/token",
			wantClaim: "https://[2001:db8::1]:443/token", wantKey: "https://[2001:db8::1]/token"},
		{name: "keeps path case and encoding", raw: "https://op.example.com/a%2Fb/Token",
			wantClaim: "https://op.example.com/a%2Fb/Token", wantKey: "https://op.example.com/a%2Fb/Token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			require.NoError(t, err)
			assert.Equal(t, tt.wantClaim, htuClaim(u), "signed htu claim")
			assert.Equal(t, tt.wantKey, htuKey(u), "comparison key")
		})
	}
}

func TestKeyBindingHTTPClient(t *testing.T) {
	const tokenEndpoint = "https://op.example.com/token"
	rp := newKeyBoundRP(t)

	// captureClient returns an http.Client whose transport records the last
	// request
	captureClient := func(seen **http.Request) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			*seen = r
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})}
	}

	// proofHTU extracts the htu claim from the DPoP header of the request
	proofHTU := func(t *testing.T, req *http.Request) string {
		t.Helper()
		jws, err := jose.ParseSigned(req.Header.Get(oidc.DPoPHeader), []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)
		var claims oidc.DPoPProofClaims
		require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
		return claims.HTTPURI
	}

	t.Run("signs proof for the token endpoint", func(t *testing.T) {
		var seen *http.Request
		hc, err := keyBindingHTTPClient(captureClient(&seen), rp, "code", tokenEndpoint)
		require.NoError(t, err)

		// A query string must not change the pinned htu.
		req, err := http.NewRequest(http.MethodPost, tokenEndpoint+"?foo=bar", nil)
		require.NoError(t, err)
		resp, err := hc.Transport.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotNil(t, seen)
		assert.Equal(t, tokenEndpoint, proofHTU(t, seen))
	})

	t.Run("accepts equivalent variants of the token endpoint", func(t *testing.T) {
		tests := []struct {
			name       string
			configured string
			request    string
			wantHTU    string
		}{
			{name: "configured endpoint has a query string", configured: tokenEndpoint + "?tenant=42",
				request: tokenEndpoint + "?tenant=42", wantHTU: tokenEndpoint},
			{name: "configured endpoint has a fragment", configured: tokenEndpoint + "#x",
				request: tokenEndpoint, wantHTU: tokenEndpoint},
			{name: "request carries userinfo", configured: tokenEndpoint,
				request: "https://user:pw@op.example.com/token", wantHTU: tokenEndpoint},
			// A default port or a different host case on either side is
			// equivalent under RFC 3986, so the request is allowed - but the
			// proof still carries the endpoint exactly as the OP published it.
			{name: "request has default port", configured: tokenEndpoint,
				request: "https://op.example.com:443/token", wantHTU: tokenEndpoint},
			{name: "configured has default port", configured: "https://op.example.com:443/token",
				request: tokenEndpoint, wantHTU: "https://op.example.com:443/token"},
			{name: "host case differs", configured: "https://OP.Example.com/token",
				request: tokenEndpoint, wantHTU: "https://OP.Example.com/token"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var seen *http.Request
				hc, err := keyBindingHTTPClient(captureClient(&seen), rp, "code", tt.configured)
				require.NoError(t, err)
				req, err := http.NewRequest(http.MethodPost, tt.request, nil)
				require.NoError(t, err)
				_, err = hc.Transport.RoundTrip(req)
				require.NoError(t, err)
				require.NotNil(t, seen)
				assert.Equal(t, tt.wantHTU, proofHTU(t, seen))
			})
		}
	})

	t.Run("refuses another endpoint", func(t *testing.T) {
		tests := []struct {
			name    string
			request string
		}{
			{name: "other host", request: "https://evil.example.com/token"},
			{name: "other path", request: "https://op.example.com/token/../authorize"},
			{name: "other scheme", request: "http://op.example.com/token"},
			{name: "other port", request: "https://op.example.com:8443/token"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var seen *http.Request
				hc, err := keyBindingHTTPClient(captureClient(&seen), rp, "code", tokenEndpoint)
				require.NoError(t, err)
				req, err := http.NewRequest(http.MethodPost, tt.request, nil)
				require.NoError(t, err)
				_, err = hc.Transport.RoundTrip(req)
				assert.ErrorIs(t, err, ErrKeyBindingEndpoint)
				assert.NotErrorIs(t, err, ErrInvalidKeyBinding, "a runtime refusal is not a configuration error")
				assert.Nil(t, seen, "the request must not reach the network")
			})
		}
	})

	t.Run("refuses redirects", func(t *testing.T) {
		hc, err := keyBindingHTTPClient(nil, rp, "code", tokenEndpoint)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, "https://evil.example.com/", nil)
		require.NoError(t, err)
		assert.ErrorIs(t, hc.CheckRedirect(req, nil), ErrKeyBindingEndpoint)
	})

	t.Run("rejects a missing or invalid token endpoint at construction", func(t *testing.T) {
		for _, endpoint := range []string{"", "/token", "op.example.com/token", "://bad"} {
			t.Run(fmt.Sprintf("%q", endpoint), func(t *testing.T) {
				_, err := keyBindingHTTPClient(nil, rp, "code", endpoint)
				assert.ErrorIs(t, err, ErrInvalidKeyBinding)
			})
		}
	})
}

func TestAuthURLKeyBinding(t *testing.T) {
	key := mustECKey(t, elliptic.P256())
	rp := &relyingParty{oauthConfig: &oauth2.Config{
		ClientID: "client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://op.example.com/authorize"},
		Scopes:   []string{"openid"},
	}}
	require.NoError(t, WithKeyBinding(key, jose.ES256)(rp))

	raw := AuthURL("state-1", rp)
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	query := parsed.Query()

	assert.Equal(t, rp.KeyBindingThumbprint(), query.Get(oidc.DPoPJKTParam))
	assert.Contains(t, query.Get("scope"), oidc.ScopeBoundKey)
}

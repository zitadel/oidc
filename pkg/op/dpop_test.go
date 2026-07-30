package op_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	testHTM = http.MethodPost
	testHTU = "https://server.example.com/token"
)

type dpopProofOpts struct {
	typ      jose.ContentType
	iat      time.Time
	jti      string
	htm      string
	htu      string
	codeHash string
}

func defaultDPoPProofOpts() dpopProofOpts {
	return dpopProofOpts{
		typ: oidc.DPoPProofType,
		iat: time.Now(),
		jti: "e1j3V_bKic8-LAEB",
		htm: testHTM,
		htu: testHTU,
	}
}

// signDPoPProof builds a DPoP proof JWT, signed by key using alg, with an
// embedded public JWK header, as described by RFC 9449, Section 4.2.
func signDPoPProof(t *testing.T, key any, alg jose.SignatureAlgorithm, opts dpopProofOpts) string {
	t.Helper()
	so := (&jose.SignerOptions{EmbedJWK: true}).WithType(opts.typ)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, so)
	require.NoError(t, err)

	claims := oidc.DPoPProofClaims{
		JWTID:      opts.jti,
		HTTPMethod: opts.htm,
		HTTPURI:    opts.htu,
		IssuedAt:   oidc.FromTime(opts.iat),
		CodeHash:   opts.codeHash,
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	proof, err := jws.CompactSerialize()
	require.NoError(t, err)
	return proof
}

func dpopHeader(proof string) http.Header {
	h := make(http.Header)
	if proof != "" {
		h.Set(oidc.DPoPHeader, proof)
	}
	return h
}

func jktOf(t *testing.T, pub any) string {
	t.Helper()
	jwk := &jose.JSONWebKey{Key: pub}
	jkt, err := oidc.JWKThumbprint(jwk)
	require.NoError(t, err)
	return jkt
}

func newVerifier(now time.Time) *op.DPoPProofVerifier {
	v := op.NewDPoPProofVerifier()
	v.Now = func() time.Time { return now }
	return v
}

func TestDPoPProofVerifier_Verify_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)

	proof := signDPoPProof(t, key, jose.ES256, defaultDPoPProofOpts())
	v := newVerifier(now)

	cnf, err := v.Verify(dpopHeader(proof), testHTM, testHTU, jkt, "")
	require.NoError(t, err)
	require.NotNil(t, cnf)
	assert.NotEmpty(t, cnf.JWK)

	var m map[string]any
	require.NoError(t, json.Unmarshal(cnf.JWK, &m))
	assert.ElementsMatch(t, []string{"kty", "crv", "x", "y"}, keysOf(m))
}

func TestDPoPProofVerifier_Verify_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)

	proof := signDPoPProof(t, key, jose.RS256, defaultDPoPProofOpts())
	v := newVerifier(now)

	cnf, err := v.Verify(dpopHeader(proof), testHTM, testHTU, jkt, "")
	require.NoError(t, err)
	require.NotNil(t, cnf)
}

func TestDPoPProofVerifier_Verify_EdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, pub)

	proof := signDPoPProof(t, priv, jose.EdDSA, defaultDPoPProofOpts())
	v := newVerifier(now)

	cnf, err := v.Verify(dpopHeader(proof), testHTM, testHTU, jkt, "")
	require.NoError(t, err)
	require.NotNil(t, cnf)
}

func TestDPoPProofVerifier_Verify_CodeBinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)
	const code = "SplxlOBeZQQYbYS6WxSbIA"

	opts := defaultDPoPProofOpts()
	opts.codeHash = oidc.CodeHash(code)
	proof := signDPoPProof(t, key, jose.ES256, opts)
	v := newVerifier(now)

	cnf, err := v.Verify(dpopHeader(proof), testHTM, testHTU, jkt, code)
	require.NoError(t, err)
	require.NotNil(t, cnf)
}

func TestDPoPProofVerifier_Verify_NormalizedHTU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)
	opts := defaultDPoPProofOpts()
	opts.htu = "HTTPS://SERVER.EXAMPLE.COM:443/a/../token?ignored=true#ignored"
	proof := signDPoPProof(t, key, jose.ES256, opts)

	cnf, err := newVerifier(now).Verify(dpopHeader(proof), testHTM, testHTU, jkt, "")
	require.NoError(t, err)
	require.NotNil(t, cnf)
}

func TestDPoPProofVerifier_Verify_DoesNotCollapseEmptyPathSegments(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)
	opts := defaultDPoPProofOpts()
	opts.htu = "https://server.example.com/a//token"
	proof := signDPoPProof(t, key, jose.ES256, opts)

	_, err = newVerifier(now).Verify(dpopHeader(proof), testHTM, "https://server.example.com/a/token", jkt, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "htu does not match")
}

func TestDPoPProofVerifier_CustomAlgorithmsCannotEnableHMAC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	v := newVerifier(now)
	v.SupportedSignAlgs = []jose.SignatureAlgorithm{jose.HS256}

	_, err = v.Verify(dpopHeader(hmacSignedProof(t, defaultDPoPProofOpts())), testHTM, testHTU, jktOf(t, &key.PublicKey), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed DPoP proof")
}

// TestDPoPProofVerifier_Verify_RejectsJSONSerialization ensures a DPoP proof
// must use the JWS Compact Serialization.
//
// This is a regression test for a real bypass. jose.ParseSigned also accepts
// the JWS JSON Serialization, whose unprotected header is NOT covered by the
// signature, and Signature.Header merges the protected and unprotected
// headers. Reading typ/jwk from the merged header therefore let an attacker
// take any JWS signed by the binding key whose protected header happened to
// omit typ and jwk, re-serialize it as flattened JSON with attacker-chosen
// unprotected typ and jwk, and have it accepted as a valid proof. Key reuse
// across protocols is only a SHOULD-NOT in the spec, so this was reachable.
func TestDPoPProofVerifier_Verify_RejectsJSONSerialization(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)
	pub := &jose.JSONWebKey{Key: key.Public()}

	// A JWS by the binding key whose protected header carries only alg.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)
	payload, err := json.Marshal(oidc.DPoPProofClaims{
		JWTID: "e1j3V_bKic8-LAEB", HTTPMethod: testHTM,
		HTTPURI: testHTU, IssuedAt: oidc.FromTime(now),
	})
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	// Without a protected typ/jwk the compact form is correctly rejected.
	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	_, err = newVerifier(now).Verify(dpopHeader(compact), testHTM, testHTU, jkt, "")
	require.Error(t, err)

	// Smuggling typ and jwk through the unprotected header must not help.
	var flat map[string]any
	require.NoError(t, json.Unmarshal([]byte(jws.FullSerialize()), &flat))
	pubJSON, err := pub.MarshalJSON()
	require.NoError(t, err)
	var pubMap map[string]any
	require.NoError(t, json.Unmarshal(pubJSON, &pubMap))
	flat["header"] = map[string]any{"typ": string(oidc.DPoPProofType), "jwk": pubMap}
	forged, err := json.Marshal(flat)
	require.NoError(t, err)

	_, err = newVerifier(now).Verify(dpopHeader(string(forged)), testHTM, testHTU, jkt, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed DPoP proof")

	// The general JSON serialization must be rejected too, even when the
	// protected header is fully populated.
	valid := signDPoPProof(t, key, jose.ES256, defaultDPoPProofOpts())
	parts := strings.Split(valid, ".")
	require.Len(t, parts, 3)
	general, err := json.Marshal(map[string]any{
		"payload": parts[1],
		"signatures": []map[string]any{{
			"protected": parts[0],
			"signature": parts[2],
		}},
	})
	require.NoError(t, err)
	_, err = newVerifier(now).Verify(dpopHeader(string(general)), testHTM, testHTU, jkt, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed DPoP proof")
}

// TestDPoPProofVerifier_Verify_SpecFixture verifies the exact non-normative
// DPoP proof example from OpenID Connect Key Binding 1.0, Section 2.3,
// including the dpop_jkt value from the Section 2.1 example Authentication
// Request. Both values were independently recomputed and cross-checked
// against RFC 7638 and this implementation's CodeHash before being pinned
// here.
func TestDPoPProofVerifier_Verify_SpecFixture(t *testing.T) {
	const proof = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6InVrcHYzZlU2dHFRS2FVd2NkQkFRb0szSUh2SklXX185eU5kMW9SN3F2WmMiLCJ5IjoibkJCeFhyeDBOeml3Z19ldmZVTVVVZ25HS0tVZjJBVHBXRzlFb2puVW9VNCJ9LCJ0eXAiOiJkcG9wK2p3dCJ9.eyJjX3MyNTYiOiJvMXVCcDllU2UzRHNtU2NOMGpZcmlGZ0tLRmRLLUJMeXdDOVdScFY1R0c4IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNzYxOTM3NDQ5LCJqdGkiOiJJUVM1dFlQLWJwQlB0SnNvclQ0ejdnIn0.ay7H-sV7o_NE19Qfdq7oFNZ_oH-8LRw7_dgiTRQAUusLjEhgzNYR1ZU1T6IZGopiTEk55LPu_g0gKKku96d4kA"
	const dpopJKT = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"
	const code = "SplxlOBeZQQYbYS6WxSbIA"

	v := newVerifier(time.Unix(1761937449, 0))
	cnf, err := v.Verify(dpopHeader(proof), http.MethodPost, "https://server.example.com/token", dpopJKT, code)
	require.NoError(t, err)
	require.NotNil(t, cnf)

	var m map[string]any
	require.NoError(t, json.Unmarshal(cnf.JWK, &m))
	assert.Equal(t, "EC", m["kty"])
	assert.Equal(t, "P-256", m["crv"])
}

func TestDPoPProofVerifier_Verify_Negative(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)

	tests := []struct {
		name    string
		header  http.Header
		htm     string
		htu     string
		jkt     string
		code    string
		wantErr string
	}{
		{
			name:    "missing DPoP header",
			header:  dpopHeader(""),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "missing DPoP header",
		},
		{
			name: "multiple DPoP headers",
			header: func() http.Header {
				h := dpopHeader(signDPoPProof(t, key, jose.ES256, defaultDPoPProofOpts()))
				h.Add(oidc.DPoPHeader, "another-value")
				return h
			}(),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "multiple DPoP headers",
		},
		{
			name:    "malformed JWT",
			header:  dpopHeader("not-a-jwt"),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "malformed DPoP proof",
		},
		{
			name:    "unsupported alg HS256",
			header:  dpopHeader(hmacSignedProof(t, defaultDPoPProofOpts())),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "malformed DPoP proof",
		},
		{
			name:    "alg none",
			header:  dpopHeader(unsecuredJWS(t, map[string]any{"alg": "none", "typ": "dpop+jwt"}, defaultDPoPProofOpts())),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "malformed DPoP proof",
		},
		{
			name: "wrong typ",
			header: dpopHeader(func() string {
				o := defaultDPoPProofOpts()
				o.typ = "JWT"
				return signDPoPProof(t, key, jose.ES256, o)
			}()),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "typ must be",
		},
		{
			name:    "missing jwk header",
			header:  dpopHeader(noJWKProof(t, key, defaultDPoPProofOpts())),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "missing jwk header",
		},
		{
			name: "htm mismatch",
			header: dpopHeader(func() string {
				o := defaultDPoPProofOpts()
				o.htm = http.MethodGet
				return signDPoPProof(t, key, jose.ES256, o)
			}()),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "htm does not match",
		},
		{
			name: "htu mismatch",
			header: dpopHeader(func() string {
				o := defaultDPoPProofOpts()
				o.htu = "https://attacker.example.com/token"
				return signDPoPProof(t, key, jose.ES256, o)
			}()),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "htu does not match",
		},
		{
			name: "stale iat",
			header: dpopHeader(func() string {
				o := defaultDPoPProofOpts()
				o.iat = now.Add(-10 * time.Minute)
				return signDPoPProof(t, key, jose.ES256, o)
			}()),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "iat is outside",
		},
		{
			name: "future iat",
			header: dpopHeader(func() string {
				o := defaultDPoPProofOpts()
				o.iat = now.Add(10 * time.Minute)
				return signDPoPProof(t, key, jose.ES256, o)
			}()),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "iat is outside",
		},
		{
			name: "missing jti",
			header: dpopHeader(func() string {
				o := defaultDPoPProofOpts()
				o.jti = ""
				return signDPoPProof(t, key, jose.ES256, o)
			}()),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			wantErr: "missing jti",
		},
		{
			name: "c_s256 missing",
			header: dpopHeader(
				signDPoPProof(t, key, jose.ES256, defaultDPoPProofOpts()),
			),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			code:    "SplxlOBeZQQYbYS6WxSbIA",
			wantErr: "c_s256 does not match",
		},
		{
			name: "c_s256 mismatch",
			header: dpopHeader(func() string {
				o := defaultDPoPProofOpts()
				o.codeHash = oidc.CodeHash("some-other-code")
				return signDPoPProof(t, key, jose.ES256, o)
			}()),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     jkt,
			code:    "SplxlOBeZQQYbYS6WxSbIA",
			wantErr: "c_s256 does not match",
		},
		{
			name:    "thumbprint mismatch",
			header:  dpopHeader(signDPoPProof(t, key, jose.ES256, defaultDPoPProofOpts())),
			htm:     testHTM,
			htu:     testHTU,
			jkt:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantErr: "does not match the committed dpop_jkt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newVerifier(now)
			_, err := v.Verify(tt.header, tt.htm, tt.htu, tt.jkt, tt.code)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// hmacSignedProof builds a DPoP-shaped proof signed with HS256, which must
// be rejected because DefaultDPoPSigningAlgs excludes symmetric algorithms.
func hmacSignedProof(t *testing.T, opts dpopProofOpts) string {
	t.Helper()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	so := (&jose.SignerOptions{}).WithType(opts.typ)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, so)
	require.NoError(t, err)
	claims := oidc.DPoPProofClaims{
		JWTID:      opts.jti,
		HTTPMethod: opts.htm,
		HTTPURI:    opts.htu,
		IssuedAt:   oidc.FromTime(opts.iat),
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	proof, err := jws.CompactSerialize()
	require.NoError(t, err)
	return proof
}

// unsecuredJWS hand-builds a compact JWS with an arbitrary header and no
// signature, to simulate an alg:none downgrade attack.
func unsecuredJWS(t *testing.T, header map[string]any, opts dpopProofOpts) string {
	t.Helper()
	claims := oidc.DPoPProofClaims{
		JWTID:      opts.jti,
		HTTPMethod: opts.htm,
		HTTPURI:    opts.htu,
		IssuedAt:   oidc.FromTime(opts.iat),
	}
	payloadBytes, err := json.Marshal(claims)
	require.NoError(t, err)
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	return b64url(headerBytes) + "." + b64url(payloadBytes) + "."
}

// noJWKProof signs a proof without embedding a jwk header, which is
// required by RFC 9449, Section 4.2.
func noJWKProof(t *testing.T, key any, opts dpopProofOpts) string {
	t.Helper()
	so := (&jose.SignerOptions{}).WithType(opts.typ)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, so)
	require.NoError(t, err)
	claims := oidc.DPoPProofClaims{
		JWTID:      opts.jti,
		HTTPMethod: opts.htm,
		HTTPURI:    opts.htu,
		IssuedAt:   oidc.FromTime(opts.iat),
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	proof, err := jws.CompactSerialize()
	require.NoError(t, err)
	return proof
}

// fixedSizeBytes returns the big-endian bytes of n, left-padded with zeros
// to size bytes, as required for JWK EC coordinate encoding.
func fixedSizeBytes(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func b64url(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		chunk := b[i:min(i+3, len(b))]
		var n int
		for _, c := range chunk {
			n = n<<8 | int(c)
		}
		n <<= uint(8 * (3 - len(chunk)))
		nChars := len(chunk) + 1
		for j := 0; j < nChars; j++ {
			out = append(out, alphabet[(n>>uint(18-6*j))&0x3f])
		}
	}
	return string(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestDPoPProofVerifier_Verify_UndersizedRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	now := time.Now()
	jkt := jktOf(t, &key.PublicKey)

	proof := signDPoPProof(t, key, jose.RS256, defaultDPoPProofOpts())
	v := newVerifier(now)

	_, err = v.Verify(dpopHeader(proof), testHTM, testHTU, jkt, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key size")
}

// TestDPoPProofVerifier_Verify_UnsupportedECCurve uses a hand-crafted
// (not validly signed) proof, because go-jose's ES256 signer itself
// enforces the P-256 curve and would refuse to produce a P-224-keyed
// proof.
//
// go-jose's own JWK decoder only recognizes the P-256/P-384/P-521 curve
// names and already rejects a "P-224" member at parse time -- before this
// implementation's own curve allow-list in checkDPoPKeyStrength ever runs.
// The two layers overlap by construction (checkDPoPKeyStrength allows
// exactly the curves go-jose can parse), so this test only asserts that
// the request is rejected end-to-end with a curve-related error, not
// which layer caught it.
func TestDPoPProofVerifier_Verify_UnsupportedECCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	// go-jose refuses to compute a thumbprint (or marshal) a P-224 key (it
	// only recognizes P-256/384/521), so the expected dpop_jkt is left as
	// an arbitrary placeholder: checkDPoPKeyStrength must reject the curve
	// before the thumbprint comparison is ever reached.
	const jkt = "irrelevant-key-strength-is-checked-first"

	// The JWK itself is built by hand from the raw coordinates for the
	// same reason.
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-224",
			"x":   b64url(fixedSizeBytes(key.X, byteLen)),
			"y":   b64url(fixedSizeBytes(key.Y, byteLen)),
		},
	}
	proof := handcraftedDPoPProof(t, header, defaultDPoPProofOpts(), make([]byte, 64))
	v := newVerifier(now)

	_, err = v.Verify(dpopHeader(proof), testHTM, testHTU, jkt, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "curve")
}

// handcraftedDPoPProof builds a compact JWS by hand from header and the
// claims described by opts, with an arbitrary (not necessarily valid)
// signature. Useful for constructing structurally-valid proofs that
// go-jose's own signer would refuse to produce.
func handcraftedDPoPProof(t *testing.T, header map[string]any, opts dpopProofOpts, sig []byte) string {
	t.Helper()
	claims := oidc.DPoPProofClaims{
		JWTID:      opts.jti,
		HTTPMethod: opts.htm,
		HTTPURI:    opts.htu,
		IssuedAt:   oidc.FromTime(opts.iat),
		CodeHash:   opts.codeHash,
	}
	payloadBytes, err := json.Marshal(claims)
	require.NoError(t, err)
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	return b64url(headerBytes) + "." + b64url(payloadBytes) + "." + b64url(sig)
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

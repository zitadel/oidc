package rp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/google/uuid"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	ErrInvalidKeyBinding      = errors.New("invalid key binding configuration")
	ErrKeyBindingIDToken      = errors.New("invalid key-bound ID token")
	ErrKeyBindingConfirmation = errors.New("ID token confirmation does not match the binding key")
)

type keyBinding struct {
	signer     jose.Signer
	thumbprint string
}

// KeyBindingRelyingParty is implemented by RPs configured with
// [WithKeyBinding].
type KeyBindingRelyingParty interface {
	RelyingParty
	KeyBindingThumbprint() string
	SignDPoPProof(method, htu, code string) (string, error)
}

// WithKeyBinding enables OpenID Connect Key Binding for the authorization code,
// refresh and device authorization flows. The RP appends the `bound_key` scope,
// adds the `dpop_jkt` authorization request parameter, signs a DPoP proof for each
// token request, and verifies that the returned ID Token is actually bound to
// the provided signer.
//
// Signer may be any [crypto.Signer], including an HSM-backed signer. alg must
// be an asymmetric JWS algorithm supported by the signer's key.
func WithKeyBinding(signer crypto.Signer, alg jose.SignatureAlgorithm) Option {
	return func(rp *relyingParty) error {
		if rp.oauth2Only {
			return fmt.Errorf("%w: key binding requires OpenID Connect", ErrInvalidOption)
		}
		if nilCryptoSigner(signer) {
			return ErrInvalidKeyBinding
		}
		// Catch any signer alg mismatches early
		if !keyBindingAlgMatchesKey(alg, signer.Public()) {
			return fmt.Errorf("%w: algorithm %q does not match the signer's public key", ErrInvalidKeyBinding, alg)
		}
		// Reject a key the OP will reject anyway
		if err := oidc.ValidateDPoPKeyStrength(signer.Public()); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKeyBinding, err)
		}
		publicJWK := &jose.JSONWebKey{Key: signer.Public(), Algorithm: string(alg)}
		thumbprint, err := oidc.JWKThumbprint(publicJWK)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKeyBinding, err)
		}
		opaqueSigner := cryptosigner.Opaque(joseCryptoSigner{Signer: signer})
		proofSigner, err := jose.NewSigner(
			jose.SigningKey{Algorithm: alg, Key: keyBindingOpaqueSigner{OpaqueSigner: opaqueSigner, publicJWK: publicJWK}},
			(&jose.SignerOptions{EmbedJWK: true}).WithType(oidc.DPoPProofType),
		)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKeyBinding, err)
		}
		rp.keyBinding = &keyBinding{signer: proofSigner, thumbprint: thumbprint}
		if !slices.Contains(rp.oauthConfig.Scopes, oidc.ScopeBoundKey) {
			rp.oauthConfig.Scopes = append(slices.Clone(rp.oauthConfig.Scopes), oidc.ScopeBoundKey)
		}
		return nil
	}
}

// joseCryptoSigner corrects rsa.PSSSaltLengthAuto used by cryptosigner.Opaque
// to the hash-length salt required by JWA for PS256, PS384, and PS512.
type joseCryptoSigner struct {
	crypto.Signer
}

func (s joseCryptoSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		corrected := *pss
		corrected.SaltLength = rsa.PSSSaltLengthEqualsHash
		opts = &corrected
	}
	return s.Signer.Sign(random, digest, opts)
}

type keyBindingOpaqueSigner struct {
	jose.OpaqueSigner
	publicJWK *jose.JSONWebKey
}

func (s keyBindingOpaqueSigner) Public() *jose.JSONWebKey {
	return s.publicJWK
}

func nilCryptoSigner(signer crypto.Signer) bool {
	if signer == nil {
		return true
	}
	value := reflect.ValueOf(signer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (rp *relyingParty) KeyBindingThumbprint() string {
	if rp.keyBinding == nil {
		return ""
	}
	return rp.keyBinding.thumbprint
}

func (rp *relyingParty) SignDPoPProof(method, htu, code string) (string, error) {
	if rp.keyBinding == nil {
		return "", ErrInvalidKeyBinding
	}
	return rp.keyBinding.proof(method, htu, code)
}

func keyBindingRP(rp RelyingParty) (KeyBindingRelyingParty, bool) {
	configured, ok := rp.(KeyBindingRelyingParty)
	return configured, ok && configured.KeyBindingThumbprint() != ""
}

func isAsymmetricKeyBindingAlgorithm(alg jose.SignatureAlgorithm) bool {
	switch alg {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.EdDSA:
		return true
	default:
		return false
	}
}

// keyBindingAlgMatchesKey reports whether alg can be produced by the public
// key pub. For the standard Go key types the pairing is fully determined (an
// EC key only matches the ES alg for its curve, an Ed25519 key only EdDSA, an
// RSA key any RS*/PS* alg). For opaque or KMS-backed keys that do not expose a
// standard public key type it falls back to requiring an asymmetric alg and
// lets the signer reject a genuine mismatch.
func keyBindingAlgMatchesKey(alg jose.SignatureAlgorithm, pub crypto.PublicKey) bool {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		switch alg {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return true
		default:
			return false
		}
	case *ecdsa.PublicKey:
		switch alg {
		case jose.ES256:
			return key.Curve == elliptic.P256()
		case jose.ES384:
			return key.Curve == elliptic.P384()
		case jose.ES512:
			return key.Curve == elliptic.P521()
		default:
			return false
		}
	case ed25519.PublicKey:
		return alg == jose.EdDSA
	default:
		return isAsymmetricKeyBindingAlgorithm(alg)
	}
}

func (k *keyBinding) proof(method, tokenEndpoint, code string) (string, error) {
	claims := oidc.DPoPProofClaims{
		JWTID:      uuid.NewString(),
		HTTPMethod: method,
		HTTPURI:    tokenEndpoint,
		IssuedAt:   oidc.FromTime(time.Now()),
	}
	if code != "" {
		claims.CodeHash = oidc.CodeHash(code)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed, err := k.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

type keyBindingTransport struct {
	base          http.RoundTripper
	binding       KeyBindingRelyingParty
	code          string
	tokenEndpoint string
}

func (t *keyBindingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	htu := *req.URL
	htu.RawQuery = ""
	htu.ForceQuery = false
	htu.Fragment = ""
	htu.RawFragment = ""

	// Only ever sign a proof for the configured token endpoint. Without this,
	// a 307/308 redirect from the token endpoint would make net/http replay the
	// POST body (authorization code and client secret) to the redirect target,
	// and this transport would helpfully mint a fresh proof for that host,
	// disclosing c_s256 = SHA256(code) to it.
	if t.tokenEndpoint == "" || htu.String() != t.tokenEndpoint {
		return nil, fmt.Errorf("%w: refusing to sign a DPoP proof for %q, expected the token endpoint %q",
			ErrInvalidKeyBinding, htu.String(), t.tokenEndpoint)
	}

	proof, err := t.binding.SignDPoPProof(req.Method, htu.String(), t.code)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.Header.Set(oidc.DPoPHeader, proof)
	return t.base.RoundTrip(req)
}

// keyBindingHTTPClient returns a shallow copy of client whose transport adds a
// DPoP proof to a single token-endpoint request. tokenEndpoint pins the only
// URL a proof will be signed for.
func keyBindingHTTPClient(client *http.Client, binding KeyBindingRelyingParty, code, tokenEndpoint string) *http.Client {
	clone := http.Client{}
	if client != nil {
		clone = *client
	}
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone.Transport = &keyBindingTransport{
		base:          base,
		binding:       binding,
		code:          code,
		tokenEndpoint: tokenEndpoint,
	}
	// Refuse redirects rather than re-POST the code to another host.
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("%w: token endpoint redirect to %q refused", ErrInvalidKeyBinding, req.URL.Redacted())
	}
	return &clone
}

// verifyKeyBindingIDToken checks that token is actually bound to the RP's
// binding key, by requiring the protected `typ` header to be
// [oidc.IDTokenTypeDPoP] and cnf.jwk to be the key identified by expectedJKT.
// The token is re-parsed here solely to reach the protected header and the
// `cnf` claim, which the generic claims types do not expose.
func verifyKeyBindingIDToken(token string, alg jose.SignatureAlgorithm, expectedJKT string) error {
	signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{alg})
	if err != nil || len(signed.Signatures) != 1 {
		return ErrKeyBindingIDToken
	}
	typ, _ := signed.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	if typ != string(oidc.IDTokenTypeDPoP) {
		return fmt.Errorf("%w: unexpected typ %q", ErrKeyBindingIDToken, typ)
	}
	// Safe: the signature over this exact token string was already verified by
	// the caller (see the contract above), so the payload is authentic. Parsing
	// it again only to read `cnf` avoids re-implementing signature checks.
	payload := signed.UnsafePayloadWithoutVerification()
	var claims struct {
		Confirmation *oidc.Confirmation `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Confirmation == nil {
		return fmt.Errorf("%w: missing cnf.jwk", ErrKeyBindingIDToken)
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(claims.Confirmation.JWK, &jwk); err != nil || !jwk.Valid() || !jwk.IsPublic() {
		return fmt.Errorf("%w: invalid cnf.jwk", ErrKeyBindingIDToken)
	}
	actualJKT, err := oidc.JWKThumbprint(&jwk)
	if err != nil {
		return fmt.Errorf("%w: invalid cnf.jwk", ErrKeyBindingIDToken)
	}
	if actualJKT != expectedJKT {
		return ErrKeyBindingConfirmation
	}
	return nil
}

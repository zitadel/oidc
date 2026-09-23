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
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/google/uuid"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	// ErrInvalidKeyBinding is returned when the key binding configuration is invalid.
	//
	// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
	// This API may change or be removed without a major version bump.
	ErrInvalidKeyBinding = errors.New("invalid key binding configuration")

	// ErrKeyBindingIDToken is returned when a key-bound ID token is invalid.
	//
	// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
	// This API may change or be removed without a major version bump.
	ErrKeyBindingIDToken = errors.New("invalid key-bound ID token")

	// ErrKeyBindingConfirmation is returned when the ID token confirmation
	// does not match the binding key.
	//
	// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
	// This API may change or be removed without a major version bump.
	ErrKeyBindingConfirmation = errors.New("ID token confirmation does not match the binding key")

	// ErrKeyBindingEndpoint is returned when a key-bound token request would be
	// sent anywhere other than the expected token endpoint, e.g. a redirect.
	//
	// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
	// This API may change or be removed without a major version bump.
	ErrKeyBindingEndpoint = errors.New("key-bound request refused for a URL other than the token endpoint")
)

type keyBinding struct {
	signer     jose.Signer
	thumbprint string
}

// KeyBindingRelyingParty is implemented by RPs configured with
// [WithKeyBinding].
//
// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
// This API may change or be removed without a major version bump.
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
//
// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
// This API may change or be removed without a major version bump.
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

// KeyBindingThumbprint returns the RFC 7638 SHA-256 JWK thumbprint of the
// binding key.
//
// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
// This API may change or be removed without a major version bump.
func (rp *relyingParty) KeyBindingThumbprint() string {
	if rp.keyBinding == nil {
		return ""
	}
	return rp.keyBinding.thumbprint
}

// SignDPoPProof creates and signs a DPoP proof JWT for the given HTTP method,
// URI, and optional authorization/device code.
//
// Experimental: OpenID Connect Key Binding 1.0 is a draft standard.
// This API may change or be removed without a major version bump.
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
	base             http.RoundTripper
	binding          KeyBindingRelyingParty
	code             string
	tokenEndpointURI *url.URL
}

// htuClaim returns the DPoP htu value defined in RFC 9449, section 4.2,
// i.e., removing the query and fragment from a URI.
func htuClaim(u *url.URL) string {
	n := *u
	n.User = nil
	n.RawQuery = ""
	n.ForceQuery = false
	n.Fragment = ""
	n.RawFragment = ""
	return n.String()
}

// htuKey returns a normalized version of the token endpoint URI
// for comparison per RFC 3986, sections 6.2.2 and 6.2.3.
func htuKey(u *url.URL) string {
	n := *u
	n.Scheme = strings.ToLower(n.Scheme)
	n.Host = strings.ToLower(n.Host)
	port := n.Port()

	// Trim the default port off of the host. This avoids rebuilding
	// from Hostname() as Hostname() removes the square brackets from
	// IPv6 literals.
	if n.Scheme == "https" && port == "443" {
		n.Host = strings.TrimSuffix(n.Host, ":443")
	} else if n.Scheme == "http" && port == "80" {
		n.Host = strings.TrimSuffix(n.Host, ":80")
	}
	return htuClaim(&n)
}

func (t *keyBindingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Use the normalized htuKey for correct htu comparison
	htuExpected := htuKey(t.tokenEndpointURI)
	htuGot := htuKey(req.URL)

	// Only ever sign a proof for the configured token endpoint. Without this,
	// a 307/308 redirect from the token endpoint would make net/http replay the
	// POST body (authorization code and client secret) to the redirect target,
	// and this transport would helpfully mint a fresh proof for that host,
	// disclosing c_s256 = SHA256(code) to it.
	if htuGot != htuExpected {
		return nil, fmt.Errorf("%w: got %q, expected %q", ErrKeyBindingEndpoint, htuGot, htuExpected)
	}

	// We should not perform full normalization on the actual htu claim in the DPoP proof.
	htuClaim := htuClaim(t.tokenEndpointURI)
	proof, err := t.binding.SignDPoPProof(req.Method, htuClaim, t.code)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.Header.Set(oidc.DPoPHeader, proof)
	return t.base.RoundTrip(req)
}

// keyBindingHTTPClient returns a shallow copy of client whose transport adds a
// DPoP proof to a single token-endpoint request. tokenEndpoint pins the only
// URL a proof will be signed for. The token endpoint is validated here before
// any request is made.
func keyBindingHTTPClient(client *http.Client, binding KeyBindingRelyingParty, code, tokenEndpoint string) (*http.Client, error) {
	if tokenEndpoint == "" {
		return nil, fmt.Errorf("%w: token endpoint is not set", ErrInvalidKeyBinding)
	}
	tokenEndpointURI, err := url.Parse(tokenEndpoint)
	if err != nil || !tokenEndpointURI.IsAbs() || tokenEndpointURI.Host == "" {
		return nil, fmt.Errorf("%w: invalid token endpoint %q", ErrInvalidKeyBinding, tokenEndpoint)
	}
	clone := http.Client{}
	if client != nil {
		clone = *client
	}
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone.Transport = &keyBindingTransport{
		base:             base,
		binding:          binding,
		code:             code,
		tokenEndpointURI: tokenEndpointURI,
	}
	// Refuse redirects rather than re-POST the code to another host.
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("%w: token endpoint redirect to %q refused", ErrKeyBindingEndpoint, req.URL.Redacted())
	}
	return &clone, nil
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

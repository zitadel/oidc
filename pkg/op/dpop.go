package op

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// DefaultDPoPSigningAlgs is the default, and recommended, allow-list of JWS
// algorithms accepted for DPoP proof JWTs. It excludes "none" and symmetric
// (HMAC) algorithms, which [RFC 9449, Section 4.2] forbids. It also derives the
// dpop_signing_alg_values_supported metadata (see [DPoPSigAlgorithms]), so
// discovery and the token endpoint cannot drift apart.
//
// EXPERIMENTAL: may change until v4
//
// [RFC 9449, Section 4.2]: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
var DefaultDPoPSigningAlgs = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.EdDSA,
}

// DefaultDPoPProofMaxAge is the default acceptance window for the `iat`
// claim of a DPoP proof JWT, in either direction. Since this implementation
// does not maintain a `jti` replay cache (see [RFC 9449, Section 11.1]), a
// short window is used to bound how long a captured proof remains usable.
//
// EXPERIMENTAL: may change until v4
//
// [RFC 9449, Section 11.1]: https://www.rfc-editor.org/rfc/rfc9449#section-11.1
const DefaultDPoPProofMaxAge = time.Minute

// DPoPProofVerifier validates DPoP proof JWTs per [RFC 9449, Section 4.3],
// plus the additional c_s256 and dpop_jkt bindings required by OpenID
// Connect Key Binding 1.0, Sections 2.3, 3.3 and 5.
//
// It does not implement `jti` replay detection ([RFC 9449, Section 11.1]);
// callers relying solely on this verifier should keep ProofMaxAge short.
//
// NOTE: the fields below apply only when you call Verify yourself. An OP built
// with [NewOpenIDProvider] always uses [DefaultDPoPSigningAlgs] and
// [DefaultDPoPProofMaxAge], which is what discovery advertises.
//
// EXPERIMENTAL: may change until v4
type DPoPProofVerifier struct {
	// SupportedSignAlgs is the allow-list of JWS algorithms accepted for
	// DPoP proof JWTs. Defaults to [DefaultDPoPSigningAlgs]. It MUST NOT
	// contain "none" or a symmetric (HMAC) algorithm.
	SupportedSignAlgs []jose.SignatureAlgorithm

	// ProofMaxAge bounds how far the `iat` claim of a proof may be from the
	// current time, in either direction. Defaults to [DefaultDPoPProofMaxAge].
	ProofMaxAge time.Duration

	// Now returns the current time. Defaults to time.Now; overridable for
	// tests.
	Now func() time.Time
}

// NewDPoPProofVerifier returns a DPoPProofVerifier configured with
// [DefaultDPoPSigningAlgs] and [DefaultDPoPProofMaxAge].
//
// EXPERIMENTAL: may change until v4
func NewDPoPProofVerifier() *DPoPProofVerifier {
	return &DPoPProofVerifier{
		SupportedSignAlgs: DefaultDPoPSigningAlgs,
		ProofMaxAge:       DefaultDPoPProofMaxAge,
		Now:               time.Now,
	}
}

func (v *DPoPProofVerifier) signAlgs() []jose.SignatureAlgorithm {
	algs := v.SupportedSignAlgs
	if len(algs) == 0 {
		algs = DefaultDPoPSigningAlgs
	}
	return slices.DeleteFunc(slices.Clone(algs), func(alg jose.SignatureAlgorithm) bool {
		return !isAsymmetricDPoPAlgorithm(alg)
	})
}

func isAsymmetricDPoPAlgorithm(alg jose.SignatureAlgorithm) bool {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.EdDSA:
		return true
	default:
		return false
	}
}

func (v *DPoPProofVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *DPoPProofVerifier) maxAge() time.Duration {
	if v.ProofMaxAge > 0 {
		return v.ProofMaxAge
	}
	return DefaultDPoPProofMaxAge
}

// Verify validates the single DPoP proof JWT in header against the request's
// method and target URI (htu, without query or fragment), and confirms it was
// created for the key committed to by expectedJKT. On success it returns the
// confirmation to embed in the ID Token's `cnf` claim.
//
// A non-empty boundCode (authorization code or device code) requires the proof's
// c_s256 claim to match its SHA-256 hash, per Key Binding 1.0 Sections 2.3 and
// 3.3; an empty boundCode is the Refresh Request case (Section 5), where no
// c_s256 is required.
//
// EXPERIMENTAL: may change until v4
func (v *DPoPProofVerifier) Verify(header http.Header, method, htu, expectedJKT, boundCode string) (*oidc.Confirmation, error) {
	proof, err := singleHeaderValue(header, oidc.DPoPHeader)
	if err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("%s", err.Error())
	}

	// RFC 9449 §4.3 checks 2 and 5. Do NOT substitute ParseSigned: it accepts the
	// JWS JSON Serialization, whose unprotected header is not covered by the
	// signature, letting an attacker inject `typ` and `jwk` and pass an unrelated
	// JWS off as a proof. A proof is a JWT, so compact serialization is required
	// (RFC 7519 §3). This also enforces alg is in v.signAlgs().
	jws, err := jose.ParseSignedCompact(proof, v.signAlgs())
	if err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("malformed DPoP proof: %s", err.Error())
	}
	if len(jws.Signatures) != 1 {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("DPoP proof must have exactly one signature")
	}
	sig := jws.Signatures[0]

	// Every header below MUST be read from sig.Protected, never sig.Header:
	// sig.Header merges the protected and unprotected headers and is therefore
	// not integrity protected. Compact serialization has no unprotected
	// header, but read from Protected regardless so this stays correct if the
	// parser above is ever changed.
	if len(sig.Unprotected.ExtraHeaders) > 0 || sig.Unprotected.JSONWebKey != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("DPoP proof must not have an unprotected header")
	}

	// Check 4: typ must be dpop+jwt, in the protected header.
	typ, _ := sig.Protected.ExtraHeaders[jose.HeaderType].(string)
	if typ != string(oidc.DPoPProofType) {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("typ must be %q", oidc.DPoPProofType)
	}

	// Checks 6 and 7: jwk header must be present, integrity protected, and a
	// public key. jose already rejects an embedded private or symmetric key
	// (see (*rawJSONWebSignature).sanitized), but we check explicitly for a
	// precise error and defense in depth.
	jwk := sig.Protected.JSONWebKey
	if jwk == nil {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("missing jwk header")
	}
	if !jwk.Valid() || !jwk.IsPublic() {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("jwk header must be a public key")
	}
	if err := oidc.ValidateDPoPKeyStrength(jwk.Key); err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("%s", err.Error())
	}

	// Check 6: signature verifies with the embedded key. Reuse the
	// already-parsed jwk; do not re-parse the key material.
	payload, err := jws.Verify(jwk)
	if err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("signature verification failed")
	}

	claims := new(oidc.DPoPProofClaims)
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("malformed proof claims")
	}

	// Check 3: required claims.
	if claims.JWTID == "" {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("missing jti claim")
	}
	if claims.HTTPMethod == "" {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("missing htm claim")
	}
	if claims.HTTPURI == "" {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("missing htu claim")
	}
	if claims.IssuedAt == 0 {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("missing iat claim")
	}

	// Check 8: htm matches.
	if claims.HTTPMethod != method {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("htm does not match the request method")
	}

	// Check 9: htu matches, ignoring query and fragment, with syntax- and
	// scheme-based normalization (RFC 3986 §§6.2.2, 6.2.3).
	wantHTU, err := normalizeHTU(htu)
	if err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("invalid configured token endpoint")
	}
	gotHTU, err := normalizeHTU(claims.HTTPURI)
	if err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("invalid htu claim")
	}
	if gotHTU != wantHTU {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("htu does not match the request URI")
	}

	// Check 11: iat is within the acceptance window.
	iat := claims.IssuedAt.AsTime()
	if age := v.now().Sub(iat); age > v.maxAge() || age < -v.maxAge() {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("iat is outside the acceptable window")
	}

	// OpenID Connect Key Binding 1.0, §§2.3/3.3: the proof must be bound to
	// the authorization code (or device code) of this token request.
	if boundCode != "" {
		want := oidc.CodeHash(boundCode)
		if !constantTimeEqual(claims.CodeHash, want) {
			return nil, oidc.ErrInvalidDPoPProof().WithDescription("c_s256 does not match the presented code")
		}
	}

	// OpenID Connect Key Binding 1.0, §2.1: the proof key must match the
	// thumbprint committed to in the dpop_jkt Authentication Request
	// parameter.
	gotJKT, err := oidc.JWKThumbprint(jwk)
	if err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("unable to compute JWK thumbprint")
	}
	if !constantTimeEqual(gotJKT, expectedJKT) {
		return nil, oidc.ErrInvalidDPoPProof().WithDescription("the proof key does not match the committed dpop_jkt")
	}

	// Canonicalize before use: strips kid/use/alg/x5c and any other
	// attacker- or client-supplied extras, and keeps the value stable
	// across a refresh (OpenID Connect Key Binding 1.0, Section 5).
	canonical, err := oidc.CanonicalJWK(jwk)
	if err != nil {
		return nil, oidc.ErrInvalidDPoPProof().WithParent(err).WithDescription("unable to canonicalize JWK")
	}
	return &oidc.Confirmation{JWK: canonical}, nil
}

// verifyBoundKey verifies a token request only when its persisted request is
// key-bound. Requests without a binding ignore DPoP headers, as required for
// compatibility with DPoP-bound access-token clients.
func verifyBoundKey(header http.Header, method, htu string, request IDTokenRequest, boundCode string) (*oidc.Confirmation, error) {
	jkt, err := boundKeyThumbprint(request)
	if err != nil || jkt == "" {
		return nil, err
	}
	return NewDPoPProofVerifier().Verify(header, method, htu, jkt, boundCode)
}

// keyBindingIntegrated reports whether the OP's storage has integrated key
// binding, which is true exactly when the persisted request type implements
// [BoundKeyRequest].
func keyBindingIntegrated(request IDTokenRequest) (BoundKeyRequest, bool) {
	boundRequest, ok := request.(BoundKeyRequest)
	return boundRequest, ok
}

func boundKeyThumbprint(request IDTokenRequest) (string, error) {
	boundRequest, integrated := keyBindingIntegrated(request)
	if !integrated {
		// Key binding is not implemented by this storage; ignore it.
		return "", nil
	}
	jkt := boundRequest.GetDPoPJKT()
	if jkt == "" {
		// The storage does know about key binding, so a granted bound_key with
		// no persisted thumbprint is a bug in the OP, not an unsupported
		// feature. Fail closed rather than issue an unbound token.
		if slices.Contains(request.GetScopes(), oidc.ScopeBoundKey) {
			return "", oidc.ErrServerError().WithDescription("bound_key request is missing its persisted dpop_jkt")
		}
		return "", nil
	}
	if !oidc.ValidDPoPJKT(jkt) {
		return "", oidc.ErrServerError().WithDescription("bound_key request has an invalid persisted dpop_jkt")
	}
	return jkt, nil
}

func verifyProviderBoundKey(ctx context.Context, header http.Header, method string, request IDTokenRequest, boundCode string, provider any) (*oidc.Confirmation, error) {
	jkt, err := boundKeyThumbprint(request)
	if err != nil || jkt == "" {
		return nil, err
	}
	tokenEndpointer, ok := provider.(interface{ TokenEndpoint() *Endpoint })
	if !ok || tokenEndpointer.TokenEndpoint() == nil {
		return nil, oidc.ErrServerError().WithDescription("unable to determine token endpoint for bound_key request")
	}
	htu := tokenEndpointer.TokenEndpoint().Absolute(IssuerFromContext(ctx))
	return NewDPoPProofVerifier().Verify(header, method, htu, jkt, boundCode)
}

// singleHeaderValue returns the single value of the named HTTP header,
// erroring if it is absent or repeated (RFC 9449 §4.3, check 1).
func singleHeaderValue(header http.Header, name string) (string, error) {
	values := header.Values(name)
	switch len(values) {
	case 0:
		return "", fmt.Errorf("missing %s header", name)
	case 1:
		return values[0], nil
	default:
		return "", fmt.Errorf("multiple %s headers", name)
	}
}

// normalizeHTU applies RFC 3986 §6.2.2 (syntax-based) and §6.2.3
// (scheme-based) normalization to raw and strips any query and fragment,
// as recommended by RFC 9449 §4.3 for comparing the htu claim.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("htu must be an absolute HTTP URI without user information")
	}
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || u.Scheme == "http" && port == "80" || u.Scheme == "https" && port == "443" {
		if strings.Contains(hostname, ":") {
			u.Host = "[" + hostname + "]"
		} else {
			u.Host = hostname
		}
	} else {
		u.Host = net.JoinHostPort(hostname, port)
	}
	escapedPath, err := normalizePercentEncoding(u.EscapedPath())
	if err != nil {
		return "", err
	}
	if escapedPath == "" {
		escapedPath = "/"
	}
	escapedPath = removeDotSegments(escapedPath)
	u.Path, err = url.PathUnescape(escapedPath)
	if err != nil {
		return "", err
	}
	u.RawPath = escapedPath
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), nil
}

func normalizePercentEncoding(value string) (string, error) {
	var normalized strings.Builder
	normalized.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			normalized.WriteByte(value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", fmt.Errorf("invalid percent encoding")
		}
		decoded, err := url.PathUnescape(value[i : i+3])
		if err != nil || len(decoded) != 1 {
			return "", fmt.Errorf("invalid percent encoding")
		}
		if isUnreserved(decoded[0]) {
			normalized.WriteByte(decoded[0])
		} else {
			normalized.WriteByte('%')
			normalized.WriteString(strings.ToUpper(value[i+1 : i+3]))
		}
		i += 2
	}
	return normalized.String(), nil
}

func isUnreserved(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || strings.ContainsRune("-._~", rune(value))
}

// removeDotSegments implements RFC 3986 Section 5.2.4 without collapsing
// empty path segments.
func removeDotSegments(input string) string {
	var output string
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			output = removeLastPathSegment(output)
		case input == "/..":
			input = "/"
			output = removeLastPathSegment(output)
		case input == "." || input == "..":
			input = ""
		default:
			segmentEnd := strings.IndexByte(input[1:], '/')
			if input[0] != '/' {
				segmentEnd = strings.IndexByte(input, '/')
				if segmentEnd < 0 {
					segmentEnd = len(input)
				}
			} else if segmentEnd < 0 {
				segmentEnd = len(input)
			} else {
				segmentEnd++
			}
			output += input[:segmentEnd]
			input = input[segmentEnd:]
		}
	}
	return output
}

func removeLastPathSegment(value string) string {
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		return value[:index]
	}
	return ""
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// DPoPSigAlgorithms returns the JWS algorithm names to advertise as
// dpop_signing_alg_values_supported in discovery, derived from algs so
// that discovery and the DPoPProofVerifier can never drift apart.
func DPoPSigAlgorithms(algs []jose.SignatureAlgorithm) []string {
	if len(algs) == 0 {
		algs = DefaultDPoPSigningAlgs
	}
	out := make([]string, 0, len(algs))
	for _, alg := range algs {
		if isAsymmetricDPoPAlgorithm(alg) {
			out = append(out, string(alg))
		}
	}
	return out
}

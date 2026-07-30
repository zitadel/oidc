package oidc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"

	jose "github.com/go-jose/go-jose/v4"
)

// Parameters, claims and helpers for OpenID Connect Key Binding 1.0, which
// binds an ID Token to a proof-of-possession key using DPoP proofs.
//
// Key Binding is still an IETF draft, so everything in this file is
// EXPERIMENTAL: may change until v4
const (
	// ScopeBoundKey requests an ID Token bound to a proof-of-possession key.
	ScopeBoundKey = "bound_key"

	// DPoPJKTParam is the authorization request parameter carrying the
	// base64url-encoded SHA-256 JWK thumbprint of the binding key.
	DPoPJKTParam = "dpop_jkt"

	// DPoPHeader carries a DPoP proof JWT.
	DPoPHeader = "DPoP"

	// DPoPProofType is the media type used in a DPoP proof's typ header.
	DPoPProofType jose.ContentType = "dpop+jwt"

	// IDTokenTypeDPoP is the media type used for a key-bound ID Token.
	IDTokenTypeDPoP jose.ContentType = "dpop+id_token"
)

// IDTokenTypeJWT is the media type used in the protected `typ` header of a
// bearer (unbound) ID Token.
const IDTokenTypeJWT jose.ContentType = "JWT"

// Confirmation is the cnf claim of a key-bound ID Token.
//
// EXPERIMENTAL: may change until v4
type Confirmation struct {
	JWK json.RawMessage `json:"jwk"`
}

// DPoPProofClaims contains the claims used by a DPoP proof for OpenID
// Connect Key Binding.
//
// EXPERIMENTAL: may change until v4
type DPoPProofClaims struct {
	JWTID      string `json:"jti"`
	HTTPMethod string `json:"htm"`
	HTTPURI    string `json:"htu"`
	IssuedAt   Time   `json:"iat"`
	CodeHash   string `json:"c_s256,omitempty"`
}

func (c *DPoPProofClaims) UnmarshalJSON(data []byte) error {
	type claims DPoPProofClaims
	var decoded claims
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if raw, ok := fields["iat"]; ok {
		var issuedAt int64
		if bytes.Equal(raw, []byte("null")) {
			return &json.UnmarshalTypeError{Value: "null", Type: reflect.TypeOf(issuedAt), Field: "iat"}
		}
		if err := json.Unmarshal(raw, &issuedAt); err != nil {
			return err
		}
		decoded.IssuedAt = Time(issuedAt)
	}
	*c = DPoPProofClaims(decoded)
	return nil
}

// ValidDPoPJKT reports whether value is an unpadded base64url-encoded
// SHA-256 JWK thumbprint.
//
// EXPERIMENTAL: may change until v4
func ValidDPoPJKT(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// JWKThumbprint returns the RFC 7638 SHA-256 thumbprint of jwk, encoded
// with unpadded base64url.
//
// EXPERIMENTAL: may change until v4
func JWKThumbprint(jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// CanonicalJWK returns the public key members of jwk without optional or
// caller-controlled JWK metadata such as kid, use, alg, or x5c.
//
// EXPERIMENTAL: may change until v4
func CanonicalJWK(jwk *jose.JSONWebKey) (json.RawMessage, error) {
	canonical, err := json.Marshal(jose.JSONWebKey{Key: jwk.Key})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

// ValidateDPoPKeyStrength enforces minimum key strength for a DPoP
// proof-of-possession key: RSA keys must be 2048-8192 bits and EC keys must use
// curve P-256, P-384 or P-521. Ed25519 keys are always allowed, as their
// strength is fixed. Any other key type is accepted here; callers are expected
// to have already restricted the key to a public asymmetric type.
//
// Shared by the OP (validating a received proof) and the RP (validating its own
// configured binding key) so the two cannot drift apart.
//
// EXPERIMENTAL: may change until v4
func ValidateDPoPKeyStrength(key any) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < 2048 || bits > 8192 {
			return fmt.Errorf("RSA key size %d bits is not allowed", bits)
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return fmt.Errorf("EC curve %s is not allowed", k.Curve.Params().Name)
		}
	}
	return nil
}

// CodeHash returns the c_s256 value for an authorization or device code.
//
// EXPERIMENTAL: may change until v4
func CodeHash(code string) string {
	hash := sha256.Sum256([]byte(code))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

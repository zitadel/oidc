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
const (
	// DPoPJKTParam is the authorization request parameter carrying the
	// base64url-encoded SHA-256 JWK thumbprint of the binding key.
	DPoPJKTParam = "dpop_jkt"

	DPoPHeader = "DPoP"

	DPoPProofType jose.ContentType = "dpop+jwt" // DPoP proof's typ header

	IDTokenTypeDPoP jose.ContentType = "dpop+id_token" // Key bound ID Token typ header
)

// cnf claim of a key-bound ID Token.
type Confirmation struct {
	JWK json.RawMessage `json:"jwk"`
}

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
func ValidDPoPJKT(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// JWKThumbprint returns the RFC 7638 SHA-256 thumbprint of jwk, encoded
// with unpadded base64url.
func JWKThumbprint(jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// ValidateDPoPKeyStrength enforces minimum key strength for a DPoP
// proof-of-possession key: RSA 2048-8192 bits, EC curve P-256, P-384 or P-521,
// and Ed25519 (fixed strength). Other key types pass; callers are expected to
// have already restricted the key to a public asymmetric type. Shared by the OP
// and RP so the two cannot drift apart.
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
func CodeHash(code string) string {
	hash := sha256.Sum256([]byte(code))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

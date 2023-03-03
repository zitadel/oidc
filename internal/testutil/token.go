// Package testuril helps setting up required data for testing,
// such as tokens, claims and verifiers.
package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"time"

	"github.com/zitadel/oidc/v2/pkg/oidc"
	"gopkg.in/square/go-jose.v2"
)

const SignatureAlgorithm = jose.PS512

// KeySet implements oidc.Keys and
// additionally can create tokens and claims that can
// be validated by this KeySet.
type KeySet struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey

	Signer jose.Signer
}

func NewKeySet() *KeySet {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: SignatureAlgorithm, Key: privateKey}, nil)
	if err != nil {
		panic(err)
	}
	return &KeySet{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
		Signer:  signer,
	}
}

func (k *KeySet) signEncodeTokenClaims(claims any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	object, err := k.Signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	token, err := object.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return token
}

func claimsMap(claims any) map[string]any {
	data, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	dst := make(map[string]any)
	if err = json.Unmarshal(data, &dst); err != nil {
		panic(err)
	}
	return dst
}

// NewIDToken creates a new IDTokenClaims with passed data and returns a signed token and claims.
func (k *KeySet) NewIDToken(issuer, subject string, audience []string, expiration, authTime time.Time, nonce string, acr string, amr []string, clientID string, skew time.Duration, atHash string) (string, *oidc.IDTokenClaims) {
	claims := oidc.NewIDTokenClaims(issuer, subject, audience, expiration, authTime, nonce, acr, amr, clientID, skew)
	claims.AccessTokenHash = atHash
	token := k.signEncodeTokenClaims(claims)

	// set this so that assertion in tests will work
	claims.SignatureAlg = SignatureAlgorithm
	claims.Claims = claimsMap(claims)
	return token, claims
}

// NewAcccessToken creates a new AccessTokenClaims with passed data and returns a signed token and claims.
func (k *KeySet) NewAccessToken(issuer, subject string, audience []string, expiration time.Time, jwtid, clientID string, skew time.Duration) (string, *oidc.AccessTokenClaims) {
	claims := oidc.NewAccessTokenClaims(issuer, subject, audience, expiration, jwtid, clientID, skew)
	token := k.signEncodeTokenClaims(claims)

	// set this so that assertion in tests will work
	claims.SignatureAlg = SignatureAlgorithm
	claims.Claims = claimsMap(claims)
	return token, claims
}

const InvalidSignatureToken = `eyJhbGciOiJQUzUxMiJ9.eyJpc3MiOiJsb2NhbC5jb20iLCJzdWIiOiJ0aW1AbG9jYWwuY29tIiwiYXVkIjpbInVuaXQiLCJ0ZXN0IiwiNTU1NjY2Il0sImV4cCI6MTY3Nzg0MDQzMSwiaWF0IjoxNjc3ODQwMzcwLCJhdXRoX3RpbWUiOjE2Nzc4NDAzMTAsIm5vbmNlIjoiMTIzNDUiLCJhY3IiOiJzb21ldGhpbmciLCJhbXIiOlsiZm9vIiwiYmFyIl0sImF6cCI6IjU1NTY2NiJ9.DtZmvVkuE4Hw48ijBMhRJbxEWCr_WEYuPQBMY73J9TP6MmfeNFkjVJf4nh4omjB9gVLnQ-xhEkNOe62FS5P0BB2VOxPuHZUj34dNspCgG3h98fGxyiMb5vlIYAHDF9T-w_LntlYItohv63MmdYR-hPpAqjXE7KOfErf-wUDGE9R3bfiQ4HpTdyFJB1nsToYrZ9lhP2mzjTCTs58ckZfQ28DFHn_lfHWpR4rJBgvLx7IH4rMrUayr09Ap-PxQLbv0lYMtmgG1z3JK8MXnuYR0UJdZnEIezOzUTlThhCXB-nvuAXYjYxZZTR0FtlgZUHhIpYK0V2abf_Q_Or36akNCUg`

// These variables always result in a valid token
// for the same test run.
var (
	ValidIssuer     = "local.com"
	ValidSubject    = "tim@local.com"
	ValidAudience   = []string{"unit", "test"}
	ValidAuthTime   = time.Now().Add(-time.Minute)       // authtime is always 1 minute in the past
	ValidExpiration = ValidAuthTime.Add(2 * time.Minute) // token is always 1 more minute available
	ValidJWTID      = "9876"
	ValidNonce      = "12345"
	ValidACR        = "something"
	ValidAMR        = []string{"foo", "bar"}
	ValidClientID   = "555666"
	ValidSkew       = time.Second
)

// ValidIDToken returns a token and claims that are in the token.
// It uses the Valid* global variables and the token always passes
// verification within the same test run.
func (k *KeySet) ValidIDToken() (string, *oidc.IDTokenClaims) {
	return k.NewIDToken(ValidIssuer, ValidSubject, ValidAudience, ValidExpiration, ValidAuthTime, ValidNonce, ValidACR, ValidAMR, ValidClientID, ValidSkew, "")
}

// ValidAccessToken returns a token and claims that are in the token.
// It uses the Valid* global variables and the token always passes
// verification within the same test run.
func (k *KeySet) ValidAccessToken() (string, *oidc.AccessTokenClaims) {
	return k.NewAccessToken(ValidIssuer, ValidSubject, ValidAudience, ValidExpiration, ValidJWTID, ValidClientID, ValidSkew)
}

// VerifySignature implments op.KeySet.
func (k *KeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error) {
	if ctx.Err() != nil {
		return nil, err
	}

	return jws.Verify(k.Public)
}

// ACRVerify is a oidc.ACRVerifier func.
func ACRVerify(acr string) error {
	if acr != ValidACR {
		return errors.New("invalid acr")
	}
	return nil
}

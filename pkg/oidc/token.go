package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

type IDTokenClaims struct {
	Issuer                              string    `json:"iss,omitempty"`
	Subject                             string    `json:"sub,omitempty"`
	Audiences                           []string  `json:"aud,omitempty"`
	Expiration                          time.Time `json:"exp,omitempty"`
	IssuedAt                            time.Time `json:"iat,omitempty"`
	AuthTime                            time.Time `json:"auth_time,omitempty"`
	Nonce                               string    `json:"nonce,omitempty"`
	AuthenticationContextClassReference string    `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string  `json:"amr,omitempty"`
	AuthorizedParty                     string    `json:"azp,omitempty"`
	AccessTokenHash                     string    `json:"at_hash,omitempty"`

	Signature jose.SignatureAlgorithm //TODO: ???
}

func (t *IDTokenClaims) UnmarshalJSON(b []byte) error {
	var i jsonIDToken
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	t.Issuer = i.Issuer
	t.Subject = i.Subject
	// t.Audiences = strings.Split(i.Audiences, " ")
	t.Audiences = i.Audiences
	t.Expiration = time.Unix(i.Expiration, 0).UTC()
	t.IssuedAt = time.Unix(i.IssuedAt, 0).UTC()
	t.AuthTime = time.Unix(i.AuthTime, 0).UTC()
	t.Nonce = i.Nonce
	t.AuthenticationContextClassReference = i.AuthenticationContextClassReference
	t.AuthenticationMethodsReferences = i.AuthenticationMethodsReferences
	t.AuthorizedParty = i.AuthorizedParty
	t.AccessTokenHash = i.AccessTokenHash
	return nil
}

func (t *IDTokenClaims) MarshalJSON() ([]byte, error) {
	j := jsonIDToken{
		Issuer:  t.Issuer,
		Subject: t.Subject,
		// Audiences:                           strings.Join(t.Audiences, " "),
		Audiences:                           t.Audiences,
		Expiration:                          t.Expiration.Unix(),
		IssuedAt:                            t.IssuedAt.Unix(),
		AuthTime:                            t.AuthTime.Unix(),
		Nonce:                               t.Nonce,
		AuthenticationContextClassReference: t.AuthenticationContextClassReference,
		AuthenticationMethodsReferences:     t.AuthenticationMethodsReferences,
		AuthorizedParty:                     t.AuthorizedParty,
		AccessTokenHash:                     t.AccessTokenHash,
	}
	return json.Marshal(j)
}

// type jsonTime time.Time

type jsonIDToken struct {
	Issuer                              string   `json:"iss,omitempty"`
	Subject                             string   `json:"sub,omitempty"`
	Audiences                           []string `json:"aud,omitempty"`
	Expiration                          int64    `json:"exp,omitempty"`
	IssuedAt                            int64    `json:"iat,omitempty"`
	AuthTime                            int64    `json:"auth_time,omitempty"`
	Nonce                               string   `json:"nonce,omitempty"`
	AuthenticationContextClassReference string   `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string `json:"amr,omitempty"`
	AuthorizedParty                     string   `json:"azp,omitempty"`
	AccessTokenHash                     string   `json:"at_hash,omitempty"`
}

type Tokens struct {
	*oauth2.Token
	IDTokenClaims *IDTokenClaims
}

func AccessTokenHash(accessToken string, sigAlgorithm jose.SignatureAlgorithm) (string, error) {
	tokenHash, err := getHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}

	tokenHash.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := tokenHash.Sum(nil)[:tokenHash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

func getHashAlgorithm(sigAlgorithm jose.SignatureAlgorithm) (hash.Hash, error) {
	switch sigAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256:
		return sha256.New(), nil
	case jose.RS384, jose.ES384, jose.PS384:
		return sha512.New384(), nil
	case jose.RS512, jose.ES512, jose.PS512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("oidc: unsupported signing algorithm %q", sigAlgorithm)
	}
}

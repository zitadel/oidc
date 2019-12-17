package oidc

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/caos/oidc/pkg/utils"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

type IDTokenClaims struct {
	Issuer                              string
	Subject                             string
	Audiences                           []string
	Expiration                          time.Time
	IssuedAt                            time.Time
	AuthTime                            time.Time
	Nonce                               string
	AuthenticationContextClassReference string
	AuthenticationMethodsReferences     []string
	AuthorizedParty                     string
	AccessTokenHash                     string
	CodeHash                            string

	Signature jose.SignatureAlgorithm //TODO: ???
}

func (t *IDTokenClaims) UnmarshalJSON(b []byte) error {
	var i jsonIDToken
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	audience := i.Audiences
	if len(audience) == 1 {
		audience = strings.Split(audience[0], " ")
	}
	t.Issuer = i.Issuer
	t.Subject = i.Subject
	t.Audiences = audience
	t.Expiration = time.Unix(i.Expiration, 0).UTC()
	t.IssuedAt = time.Unix(i.IssuedAt, 0).UTC()
	t.AuthTime = time.Unix(i.AuthTime, 0).UTC()
	t.Nonce = i.Nonce
	t.AuthenticationContextClassReference = i.AuthenticationContextClassReference
	t.AuthenticationMethodsReferences = i.AuthenticationMethodsReferences
	t.AuthorizedParty = i.AuthorizedParty
	t.AccessTokenHash = i.AccessTokenHash
	t.CodeHash = i.CodeHash
	return nil
}

func (t *IDTokenClaims) MarshalJSON() ([]byte, error) {
	j := jsonIDToken{
		Issuer:                              t.Issuer,
		Subject:                             t.Subject,
		Audiences:                           t.Audiences,
		Expiration:                          t.Expiration.Unix(),
		IssuedAt:                            t.IssuedAt.Unix(),
		AuthTime:                            t.AuthTime.Unix(),
		Nonce:                               t.Nonce,
		AuthenticationContextClassReference: t.AuthenticationContextClassReference,
		AuthenticationMethodsReferences:     t.AuthenticationMethodsReferences,
		AuthorizedParty:                     t.AuthorizedParty,
		AccessTokenHash:                     t.AccessTokenHash,
		CodeHash:                            t.CodeHash,
	}
	return json.Marshal(j)
}

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
	CodeHash                            string   `json:"c_hash,omitempty"`
}

type Tokens struct {
	*oauth2.Token
	IDTokenClaims *IDTokenClaims
	IDToken       string
}

func ClaimHash(claim string, sigAlgorithm jose.SignatureAlgorithm) (string, error) {
	hash, err := utils.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}

	return utils.HashString(hash, claim), nil
}

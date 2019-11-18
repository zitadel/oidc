package oidc

import (
	"encoding/json"
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

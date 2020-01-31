package oidc

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/caos/oidc/pkg/utils"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

type Tokens struct {
	*oauth2.Token
	IDTokenClaims *IDTokenClaims
	IDToken       string
}

type AccessTokenClaims struct {
	Issuer                              string
	Subject                             string
	Audiences                           []string
	Expiration                          time.Time
	IssuedAt                            time.Time
	NotBefore                           time.Time
	JWTID                               string
	AuthorizedParty                     string
	Nonce                               string
	AuthTime                            time.Time
	CodeHash                            string
	AuthenticationContextClassReference string
	AuthenticationMethodsReferences     []string
	SessionID                           string
	Scopes                              []string
	ClientID                            string
	AccessTokenUseNumber                int
}

type IDTokenClaims struct {
	Issuer                              string
	Subject                             string
	Audiences                           []string
	Expiration                          time.Time
	NotBefore                           time.Time
	IssuedAt                            time.Time
	JWTID                               string
	UpdatedAt                           time.Time
	AuthorizedParty                     string
	Nonce                               string
	AuthTime                            time.Time
	AccessTokenHash                     string
	CodeHash                            string
	AuthenticationContextClassReference string
	AuthenticationMethodsReferences     []string
	ClientID                            string

	Signature jose.SignatureAlgorithm //TODO: ???
}

type jsonToken struct {
	Issuer                              string      `json:"iss,omitempty"`
	Subject                             string      `json:"sub,omitempty"`
	Audiences                           []string    `json:"aud,omitempty"`
	Expiration                          int64       `json:"exp,omitempty"`
	NotBefore                           int64       `json:"nbf,omitempty"`
	IssuedAt                            int64       `json:"iat,omitempty"`
	JWTID                               string      `json:"jti,omitempty"`
	UpdatedAt                           int64       `json:"updated_at,omitempty"`
	AuthorizedParty                     string      `json:"azp,omitempty"`
	Nonce                               string      `json:"nonce,omitempty"`
	AuthTime                            int64       `json:"auth_time,omitempty"`
	AccessTokenHash                     string      `json:"at_hash,omitempty"`
	CodeHash                            string      `json:"c_hash,omitempty"`
	AuthenticationContextClassReference string      `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string    `json:"amr,omitempty"`
	SessionID                           string      `json:"sid,omitempty"`
	Actor                               interface{} `json:"act,omitempty"` //TODO: impl
	Scopes                              string      `json:"scope,omitempty"`
	ClientID                            string      `json:"client_id,omitempty"`
	AuthorizedActor                     interface{} `json:"may_act,omitempty"` //TODO: impl
	AccessTokenUseNumber                int         `json:"at_use_nbr,omitempty"`
}

func (t *AccessTokenClaims) MarshalJSON() ([]byte, error) {
	j := jsonToken{
		Issuer:                              t.Issuer,
		Subject:                             t.Subject,
		Audiences:                           t.Audiences,
		Expiration:                          timeToJSON(t.Expiration),
		NotBefore:                           timeToJSON(t.NotBefore),
		IssuedAt:                            timeToJSON(t.IssuedAt),
		JWTID:                               t.JWTID,
		AuthorizedParty:                     t.AuthorizedParty,
		Nonce:                               t.Nonce,
		AuthTime:                            timeToJSON(t.AuthTime),
		CodeHash:                            t.CodeHash,
		AuthenticationContextClassReference: t.AuthenticationContextClassReference,
		AuthenticationMethodsReferences:     t.AuthenticationMethodsReferences,
		SessionID:                           t.SessionID,
		Scopes:                              strings.Join(t.Scopes, " "),
		ClientID:                            t.ClientID,
		AccessTokenUseNumber:                t.AccessTokenUseNumber,
	}
	return json.Marshal(j)
}

func (t *AccessTokenClaims) UnmarshalJSON(b []byte) error {
	var j jsonToken
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	audience := j.Audiences
	if len(audience) == 1 {
		audience = strings.Split(audience[0], " ")
	}
	t.Issuer = j.Issuer
	t.Subject = j.Subject
	t.Audiences = audience
	t.Expiration = time.Unix(j.Expiration, 0).UTC()
	t.NotBefore = time.Unix(j.NotBefore, 0).UTC()
	t.IssuedAt = time.Unix(j.IssuedAt, 0).UTC()
	t.JWTID = j.JWTID
	t.AuthorizedParty = j.AuthorizedParty
	t.Nonce = j.Nonce
	t.AuthTime = time.Unix(j.AuthTime, 0).UTC()
	t.CodeHash = j.CodeHash
	t.AuthenticationContextClassReference = j.AuthenticationContextClassReference
	t.AuthenticationMethodsReferences = j.AuthenticationMethodsReferences
	t.SessionID = j.SessionID
	t.Scopes = strings.Split(j.Scopes, " ")
	t.ClientID = j.ClientID
	t.AccessTokenUseNumber = j.AccessTokenUseNumber
	return nil
}

func (t *IDTokenClaims) MarshalJSON() ([]byte, error) {
	j := jsonToken{
		Issuer:                              t.Issuer,
		Subject:                             t.Subject,
		Audiences:                           t.Audiences,
		Expiration:                          timeToJSON(t.Expiration),
		NotBefore:                           timeToJSON(t.NotBefore),
		IssuedAt:                            timeToJSON(t.IssuedAt),
		JWTID:                               t.JWTID,
		UpdatedAt:                           timeToJSON(t.UpdatedAt),
		AuthorizedParty:                     t.AuthorizedParty,
		Nonce:                               t.Nonce,
		AuthTime:                            timeToJSON(t.AuthTime),
		AccessTokenHash:                     t.AccessTokenHash,
		CodeHash:                            t.CodeHash,
		AuthenticationContextClassReference: t.AuthenticationContextClassReference,
		AuthenticationMethodsReferences:     t.AuthenticationMethodsReferences,
		ClientID:                            t.ClientID,
	}
	return json.Marshal(j)
}

func (t *IDTokenClaims) UnmarshalJSON(b []byte) error {
	var i jsonToken
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

func ClaimHash(claim string, sigAlgorithm jose.SignatureAlgorithm) (string, error) {
	hash, err := utils.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}

	return utils.HashString(hash, claim), nil
}

func timeToJSON(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

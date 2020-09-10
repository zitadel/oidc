package oidc

import (
	"encoding/json"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/utils"
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
	Userinfo

	Signature jose.SignatureAlgorithm //TODO: ???
}

type jsonToken struct {
	Issuer                              string      `json:"iss,omitempty"`
	Subject                             string      `json:"sub,omitempty"`
	Audiences                           interface{} `json:"aud,omitempty"`
	Expiration                          int64       `json:"exp,omitempty"`
	NotBefore                           int64       `json:"nbf,omitempty"`
	IssuedAt                            int64       `json:"iat,omitempty"`
	JWTID                               string      `json:"jti,omitempty"`
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
	jsonUserinfo
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
	t.Issuer = j.Issuer
	t.Subject = j.Subject
	t.Audiences = audienceFromJSON(j.Audiences)
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
		AuthorizedParty:                     t.AuthorizedParty,
		Nonce:                               t.Nonce,
		AuthTime:                            timeToJSON(t.AuthTime),
		AccessTokenHash:                     t.AccessTokenHash,
		CodeHash:                            t.CodeHash,
		AuthenticationContextClassReference: t.AuthenticationContextClassReference,
		AuthenticationMethodsReferences:     t.AuthenticationMethodsReferences,
		ClientID:                            t.ClientID,
	}
	j.setUserinfo(t.Userinfo)
	return json.Marshal(j)
}

func (t *IDTokenClaims) UnmarshalJSON(b []byte) error {
	var i jsonToken
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	t.Issuer = i.Issuer
	t.Subject = i.Subject
	t.Audiences = audienceFromJSON(i.Audiences)
	t.Expiration = time.Unix(i.Expiration, 0).UTC()
	t.IssuedAt = time.Unix(i.IssuedAt, 0).UTC()
	t.AuthTime = time.Unix(i.AuthTime, 0).UTC()
	t.Nonce = i.Nonce
	t.AuthenticationContextClassReference = i.AuthenticationContextClassReference
	t.AuthenticationMethodsReferences = i.AuthenticationMethodsReferences
	t.AuthorizedParty = i.AuthorizedParty
	t.AccessTokenHash = i.AccessTokenHash
	t.CodeHash = i.CodeHash
	t.UserinfoProfile = i.UnmarshalUserinfoProfile()
	t.UserinfoEmail = i.UnmarshalUserinfoEmail()
	t.UserinfoPhone = i.UnmarshalUserinfoPhone()
	t.Address = i.UnmarshalUserinfoAddress()
	return nil
}

func (t *IDTokenClaims) GetIssuer() string {
	return t.Issuer
}

func (t *IDTokenClaims) GetAudience() []string {
	return t.Audiences
}

func (t *IDTokenClaims) GetExpiration() time.Time {
	return t.Expiration
}

func (t *IDTokenClaims) GetIssuedAt() time.Time {
	return t.IssuedAt
}

func (t *IDTokenClaims) GetNonce() string {
	return t.Nonce
}

func (t *IDTokenClaims) GetAuthenticationContextClassReference() string {
	return t.AuthenticationContextClassReference
}

func (t *IDTokenClaims) GetAuthTime() time.Time {
	return t.AuthTime
}

func (t *IDTokenClaims) GetAuthorizedParty() string {
	return t.AuthorizedParty
}

func (t *IDTokenClaims) SetSignature(alg jose.SignatureAlgorithm) {
	t.Signature = alg
}

func (j *jsonToken) UnmarshalUserinfoProfile() UserinfoProfile {
	locale, _ := language.Parse(j.Locale)
	return UserinfoProfile{
		Name:              j.Name,
		GivenName:         j.GivenName,
		FamilyName:        j.FamilyName,
		MiddleName:        j.MiddleName,
		Nickname:          j.Nickname,
		Profile:           j.Profile,
		Picture:           j.Picture,
		Website:           j.Website,
		Gender:            Gender(j.Gender),
		Birthdate:         j.Birthdate,
		Zoneinfo:          j.Zoneinfo,
		Locale:            locale,
		UpdatedAt:         time.Unix(j.UpdatedAt, 0).UTC(),
		PreferredUsername: j.PreferredUsername,
	}
}

func (j *jsonToken) UnmarshalUserinfoEmail() UserinfoEmail {
	return UserinfoEmail{
		Email:         j.Email,
		EmailVerified: j.EmailVerified,
	}
}

func (j *jsonToken) UnmarshalUserinfoPhone() UserinfoPhone {
	return UserinfoPhone{
		PhoneNumber:         j.Phone,
		PhoneNumberVerified: j.PhoneVerified,
	}
}

func (j *jsonToken) UnmarshalUserinfoAddress() *UserinfoAddress {
	if j.JsonUserinfoAddress == nil {
		return nil
	}
	return &UserinfoAddress{
		Country:       j.JsonUserinfoAddress.Country,
		Formatted:     j.JsonUserinfoAddress.Formatted,
		Locality:      j.JsonUserinfoAddress.Locality,
		PostalCode:    j.JsonUserinfoAddress.PostalCode,
		Region:        j.JsonUserinfoAddress.Region,
		StreetAddress: j.JsonUserinfoAddress.StreetAddress,
	}
}

func ClaimHash(claim string, sigAlgorithm jose.SignatureAlgorithm) (string, error) {
	hash, err := utils.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}

	return utils.HashString(hash, claim, true), nil
}

func timeToJSON(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func audienceFromJSON(i interface{}) []string {
	switch aud := i.(type) {
	case []string:
		return aud
	case []interface{}:
		audience := make([]string, len(aud))
		for i, a := range aud {
			audience[i] = a.(string)
		}
		return audience
	case string:
		return []string{aud}
	}
	return nil
}

package oidc

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/caos/oidc/pkg/utils"
	"golang.org/x/oauth2"
	"golang.org/x/text/language"
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
	UserinfoProfile
	UserinfoEmail
	UserinfoPhone
	UserinfoAddress *UserinfoAddress

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
		AuthorizedParty:                     t.AuthorizedParty,
		Nonce:                               t.Nonce,
		AuthTime:                            timeToJSON(t.AuthTime),
		AccessTokenHash:                     t.AccessTokenHash,
		CodeHash:                            t.CodeHash,
		AuthenticationContextClassReference: t.AuthenticationContextClassReference,
		AuthenticationMethodsReferences:     t.AuthenticationMethodsReferences,
		ClientID:                            t.ClientID,
	}
	j.setUserinfo(t)
	return json.Marshal(j)
}
func (t *IDTokenClaims) GetUserinfoProfile() UserinfoProfile {
	return t.UserinfoProfile
}
func (t *IDTokenClaims) GetUserinfoEmail() UserinfoEmail {
	return t.UserinfoEmail
}
func (t *IDTokenClaims) GetUserinfoPhone() UserinfoPhone {
	return t.UserinfoPhone
}
func (t *IDTokenClaims) GetAddress() *UserinfoAddress {
	return t.UserinfoAddress
}

// func (t *IDTokenClaims) GetUserinfoEmail() UserinfoEmailI {
// 	return t.UserinfoEmail
// }

// func (t *IDTokenClaims) setUserinfo(j *jsonToken) {
// 	t.setUserinfoProfile(j)
// 	t.setUserinfoEmail(j)
// 	t.setUserinfoPhone(j)
// 	t.setUserinfoAddress(j)
// }

// func (t *IDTokenClaims) setUserinfoProfile(j *jsonToken) {
// 	j.Name = t.Name
// 	j.GivenName = t.GivenName
// 	j.FamilyName = t.FamilyName
// 	j.MiddleName = t.MiddleName
// 	j.Nickname = t.Nickname
// 	j.Profile = t.Profile
// 	j.Picture = t.Picture
// 	j.Website = t.Website
// 	j.Gender = string(t.Gender)
// 	j.Birthdate = t.Birthdate
// 	j.Zoneinfo = t.Zoneinfo
// 	j.Locale = t.Locale.String()
// 	j.UpdatedAt = timeToJSON(t.UpdatedAt)
// 	j.PreferredUsername = t.PreferredUsername
// }

// func (t *IDTokenClaims) setUserinfoEmail(j *jsonToken) {
// 	j.Email = t.Email
// 	j.EmailVerified = t.EmailVerified
// }

// func (t *IDTokenClaims) setUserinfoPhone(j *jsonToken) {
// 	j.Phone = t.PhoneNumber
// 	j.PhoneVerified = t.PhoneNumberVerified
// }

// func (t *IDTokenClaims) setUserinfoAddress(j *jsonToken) {
// 	if t.UserinfoAddress == nil {
// 		return
// 	}
// 	j.jsonUserinfoAddress.Country = t.UserinfoAddress.Country
// 	j.jsonUserinfoAddress.Formatted = t.UserinfoAddress.Formatted
// 	j.jsonUserinfoAddress.Locality = t.UserinfoAddress.Locality
// 	j.jsonUserinfoAddress.PostalCode = t.UserinfoAddress.PostalCode
// 	j.jsonUserinfoAddress.Region = t.UserinfoAddress.Region
// 	j.jsonUserinfoAddress.StreetAddress = t.UserinfoAddress.StreetAddress
// }

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
	t.UserinfoProfile = i.UnmarshalUserinfoProfile()
	t.UserinfoEmail = i.UnmarshalUserinfoEmail()
	t.UserinfoPhone = i.UnmarshalUserinfoPhone()
	t.UserinfoAddress = i.UnmarshalUserinfoAddress()
	return nil
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
	if j.jsonUserinfoAddress == nil {
		return nil
	}
	return &UserinfoAddress{
		Country:       j.jsonUserinfoAddress.Country,
		Formatted:     j.jsonUserinfoAddress.Formatted,
		Locality:      j.jsonUserinfoAddress.Locality,
		PostalCode:    j.jsonUserinfoAddress.PostalCode,
		Region:        j.jsonUserinfoAddress.Region,
		StreetAddress: j.jsonUserinfoAddress.StreetAddress,
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

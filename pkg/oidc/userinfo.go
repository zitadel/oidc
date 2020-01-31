package oidc

import (
	"encoding/json"
	"time"

	"golang.org/x/text/language"
)

type Userinfo struct {
	Subject string
	Address *UserinfoAddress
	UserinfoProfile
	UserinfoEmail
	UserinfoPhone

	claims map[string]interface{}
}

type UserinfoPhone struct {
	PhoneNumber         string
	PhoneNumberVerified bool
}
type UserinfoProfile struct {
	Name              string
	GivenName         string
	FamilyName        string
	MiddleName        string
	Nickname          string
	Profile           string
	Picture           string
	Website           string
	Gender            Gender
	Birthdate         string
	Zoneinfo          string
	Locale            language.Tag
	UpdatedAt         time.Time
	PreferredUsername string
}

type Gender string

type UserinfoAddress struct {
	Formatted     string
	StreetAddress string
	Locality      string
	Region        string
	PostalCode    string
	Country       string
}

type UserinfoEmail struct {
	Email         string
	EmailVerified bool
}

func marshalUserinfoProfile(i UserinfoProfile, claims map[string]interface{}) {
	claims["name"] = i.Name
	claims["given_name"] = i.GivenName
	claims["family_name"] = i.FamilyName
	claims["middle_name"] = i.MiddleName
	claims["nickname"] = i.Nickname
	claims["profile"] = i.Profile
	claims["picture"] = i.Picture
	claims["website"] = i.Website
	claims["gender"] = i.Gender
	claims["birthdate"] = i.Birthdate
	claims["Zoneinfo"] = i.Zoneinfo
	claims["locale"] = i.Locale.String()
	claims["updated_at"] = i.UpdatedAt.UTC().Unix()
	claims["preferred_username"] = i.PreferredUsername
}

func marshalUserinfoEmail(i UserinfoEmail, claims map[string]interface{}) {
	if i.Email != "" {
		claims["email"] = i.Email
	}
	if i.EmailVerified {
		claims["email_verified"] = i.EmailVerified
	}
}

func marshalUserinfoAddress(i *UserinfoAddress, claims map[string]interface{}) {
	if i == nil {
		return
	}
	address := make(map[string]interface{})
	if i.Formatted != "" {
		address["formatted"] = i.Formatted
	}
	if i.StreetAddress != "" {
		address["street_address"] = i.StreetAddress
	}
	claims["address"] = address
}

func marshalUserinfoPhone(i UserinfoPhone, claims map[string]interface{}) {
	claims["phone_number"] = i.PhoneNumber
	claims["phone_number_verified"] = i.PhoneNumberVerified
}

func (i *Userinfo) MarshalJSON() ([]byte, error) {
	claims := i.claims
	if claims == nil {
		claims = make(map[string]interface{})
	}
	claims["sub"] = i.Subject
	marshalUserinfoAddress(i.Address, claims)
	marshalUserinfoEmail(i.UserinfoEmail, claims)
	marshalUserinfoPhone(i.UserinfoPhone, claims)
	marshalUserinfoProfile(i.UserinfoProfile, claims)
	return json.Marshal(claims)
}

func (i *Userinfo) UnmmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, i); err != nil {
		return err
	}
	return json.Unmarshal(data, i.claims)
}

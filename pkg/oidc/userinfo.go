package oidc

import (
	"encoding/json"
	"time"

	"golang.org/x/text/language"
)

type Userinfo struct {
	Subject string
	UserinfoProfile
	UserinfoEmail
	UserinfoPhone
	Address *UserinfoAddress

	Authorizations []string

	claims map[string]interface{}
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

type UserinfoEmail struct {
	Email         string
	EmailVerified bool
}

type UserinfoPhone struct {
	PhoneNumber         string
	PhoneNumberVerified bool
}

type UserinfoAddress struct {
	Formatted     string
	StreetAddress string
	Locality      string
	Region        string
	PostalCode    string
	Country       string
}

type jsonUserinfoProfile struct {
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Website           string `json:"website,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

type jsonUserinfoEmail struct {
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

type jsonUserinfoPhone struct {
	Phone         string `json:"phone_number,omitempty"`
	PhoneVerified bool   `json:"phone_number_verified,omitempty"`
}

type jsonUserinfoAddress struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

func (i *Userinfo) MarshalJSON() ([]byte, error) {
	j := new(jsonUserinfo)
	j.Subject = i.Subject
	j.setUserinfo(*i)
	j.Authorizations = i.Authorizations
	return json.Marshal(j)
}

func (i *Userinfo) UnmmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, i); err != nil {
		return err
	}
	return json.Unmarshal(data, &i.claims)
}

type jsonUserinfo struct {
	Subject string `json:"sub,omitempty"`
	jsonUserinfoProfile
	jsonUserinfoEmail
	jsonUserinfoPhone
	JsonUserinfoAddress *jsonUserinfoAddress `json:"address,omitempty"`
	Authorizations      []string             `json:"authorizations,omitempty"`
}

func (j *jsonUserinfo) setUserinfo(i Userinfo) {
	j.setUserinfoProfile(i.UserinfoProfile)
	j.setUserinfoEmail(i.UserinfoEmail)
	j.setUserinfoPhone(i.UserinfoPhone)
	j.setUserinfoAddress(i.Address)
}

func (j *jsonUserinfo) setUserinfoProfile(i UserinfoProfile) {
	j.Name = i.Name
	j.GivenName = i.GivenName
	j.FamilyName = i.FamilyName
	j.MiddleName = i.MiddleName
	j.Nickname = i.Nickname
	j.Profile = i.Profile
	j.Picture = i.Picture
	j.Website = i.Website
	j.Gender = string(i.Gender)
	j.Birthdate = i.Birthdate
	j.Zoneinfo = i.Zoneinfo
	if i.Locale != language.Und {
		j.Locale = i.Locale.String()
	}
	j.UpdatedAt = timeToJSON(i.UpdatedAt)
	j.PreferredUsername = i.PreferredUsername
}

func (j *jsonUserinfo) setUserinfoEmail(i UserinfoEmail) {
	j.Email = i.Email
	j.EmailVerified = i.EmailVerified
}

func (j *jsonUserinfo) setUserinfoPhone(i UserinfoPhone) {
	j.Phone = i.PhoneNumber
	j.PhoneVerified = i.PhoneNumberVerified
}

func (j *jsonUserinfo) setUserinfoAddress(i *UserinfoAddress) {
	if i == nil {
		return
	}
	j.JsonUserinfoAddress.Country = i.Country
	j.JsonUserinfoAddress.Formatted = i.Formatted
	j.JsonUserinfoAddress.Locality = i.Locality
	j.JsonUserinfoAddress.PostalCode = i.PostalCode
	j.JsonUserinfoAddress.Region = i.Region
	j.JsonUserinfoAddress.StreetAddress = i.StreetAddress
}

type UserInfoRequest struct {
	AccessToken string `schema:"access_token"`
}

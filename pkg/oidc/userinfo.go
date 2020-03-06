package oidc

import (
	"encoding/json"
	"time"

	"golang.org/x/text/language"
)

type userinfo interface {
	GetUserinfoProfile() UserinfoProfile
	GetUserinfoEmail() UserinfoEmail
	GetUserinfoPhone() UserinfoPhone
	GetAddress() *UserinfoAddress
}

type UserinfoProfileI interface {
	GetName() string
	GetGivenName() string
	GetFamilyName() string
	GetMiddleName() string
	GetNickname() string
	GetProfile() string
	GetPicture() string
	GetWebsite() string
	GetGender() Gender
	GetBirthdate() string
	GetZoneinfo() string
	GetLocale() language.Tag
	GetUpdatedAt() time.Time
	GetPreferredUsername() string
}

type UserinfoEmailI interface {
	GetEmail() string
	IsEmailVerified() bool
}

type Userinfo struct {
	Subject string
	Address *UserinfoAddress
	UserinfoProfile
	UserinfoEmail
	UserinfoPhone

	claims map[string]interface{}
}

type UserinfoPhoneI interface {
	GetPhoneNumber() string
	IsPhoneNumberVerified() bool
}
type UserinfoPhone struct {
	PhoneNumber         string
	PhoneNumberVerified bool
}

func (u UserinfoPhone) GetPhoneNumber() string {
	return u.PhoneNumber
}

func (u UserinfoPhone) IsPhoneNumberVerified() bool {
	return u.PhoneNumberVerified
}

type UserinfoAddressI interface {
	GetCountry() string
	GetFormatted() string
	GetLocality() string
	GetPostalCode() string
	GetRegion() string
	GetStreetAddress() string
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

func (u UserinfoProfile) GetName() string {
	return u.Name
}
func (u UserinfoProfile) GetGivenName() string {
	return u.GivenName
}
func (u UserinfoProfile) GetFamilyName() string {
	return u.FamilyName
}
func (u UserinfoProfile) GetMiddleName() string {
	return u.MiddleName
}
func (u UserinfoProfile) GetNickname() string {
	return u.Nickname
}
func (u UserinfoProfile) GetProfile() string {
	return u.Profile
}
func (u UserinfoProfile) GetPicture() string {
	return u.Picture
}
func (u UserinfoProfile) GetWebsite() string {
	return u.Website
}
func (u UserinfoProfile) GetGender() Gender {
	return u.Gender
}
func (u UserinfoProfile) GetBirthdate() string {
	return u.Birthdate
}
func (u UserinfoProfile) GetZoneinfo() string {
	return u.Zoneinfo
}
func (u UserinfoProfile) GetLocale() language.Tag {
	return u.Locale
}
func (u UserinfoProfile) GetUpdatedAt() time.Time {
	return u.UpdatedAt
}
func (u UserinfoProfile) GetPreferredUsername() string {
	return u.PreferredUsername
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

func (u UserinfoAddress) GetCountry() string {
	return u.Country
}
func (u UserinfoAddress) GetFormatted() string {
	return u.Formatted
}
func (u UserinfoAddress) GetLocality() string {
	return u.Locality
}
func (u UserinfoAddress) GetPostalCode() string {
	return u.PostalCode
}
func (u UserinfoAddress) GetRegion() string {
	return u.Region
}
func (u UserinfoAddress) GetStreetAddress() string {
	return u.StreetAddress
}

type UserinfoEmail struct {
	Email         string
	EmailVerified bool
}

func (u UserinfoEmail) GetEmail() string {
	return u.Email
}

func (u UserinfoEmail) IsEmailVerified() bool {
	return u.EmailVerified
}

type jsonUserinfo struct {
	jsonUserinfoProfile
	jsonUserinfoEmail
	jsonUserinfoPhone
	jsonUserinfoAddress *jsonUserinfoAddress `json:"address,omitempty"`
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

// func (t *Userinfo) setUserinfoProfile(j *jsonToken) {
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

// func marshalUserinfoProfile(i UserinfoProfile, claims map[string]interface{}) {
// 	claims["name"] = i.Name
// 	claims["given_name"] = i.GivenName
// 	claims["family_name"] = i.FamilyName
// 	claims["middle_name"] = i.MiddleName
// 	claims["nickname"] = i.Nickname
// 	claims["profile"] = i.Profile
// 	claims["picture"] = i.Picture
// 	claims["website"] = i.Website
// 	claims["gender"] = i.Gender
// 	claims["birthdate"] = i.Birthdate
// 	claims["Zoneinfo"] = i.Zoneinfo
// 	claims["locale"] = i.Locale.String()
// 	claims["updated_at"] = i.UpdatedAt.UTC().Unix()
// 	claims["preferred_username"] = i.PreferredUsername
// }

// func marshalUserinfoEmail(i UserinfoEmail, claims map[string]interface{}) {
// 	if i.Email != "" {
// 		claims["email"] = i.Email
// 	}
// 	if i.EmailVerified {
// 		claims["email_verified"] = i.EmailVerified
// 	}
// }

// func marshalUserinfoAddress(i *UserinfoAddress, claims map[string]interface{}) {
// 	if i == nil {
// 		return
// 	}
// 	address := make(map[string]interface{})
// 	if i.Formatted != "" {
// 		address["formatted"] = i.Formatted
// 	}
// 	if i.StreetAddress != "" {
// 		address["street_address"] = i.StreetAddress
// 	}
// 	claims["address"] = address
// }

// func marshalUserinfoPhone(i UserinfoPhone, claims map[string]interface{}) {
// 	claims["phone_number"] = i.PhoneNumber
// 	claims["phone_number_verified"] = i.PhoneNumberVerified
// }

func (i *Userinfo) MarshalJSON() ([]byte, error) {
	j := new(jsonUserinfo)
	j.setUserinfo(i)
	return json.Marshal(j)
}

func (i *Userinfo) GetAddress() *UserinfoAddress {
	return i.Address
}

func (i *Userinfo) GetUserinfoProfile() UserinfoProfile {
	return i.UserinfoProfile
}
func (i *Userinfo) GetUserinfoEmail() UserinfoEmail {
	return i.UserinfoEmail
}
func (i *Userinfo) GetUserinfoPhone() UserinfoPhone {
	return i.UserinfoPhone
}

func (j *jsonUserinfo) setUserinfo(i userinfo) {
	j.setUserinfoProfile(i.GetUserinfoProfile())
	j.setUserinfoEmail(i.GetUserinfoEmail())
	j.setUserinfoPhone(i.GetUserinfoPhone())
	j.setUserinfoAddress(i.GetAddress())
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
	j.jsonUserinfoAddress.Country = i.Country
	j.jsonUserinfoAddress.Formatted = i.Formatted
	j.jsonUserinfoAddress.Locality = i.Locality
	j.jsonUserinfoAddress.PostalCode = i.PostalCode
	j.jsonUserinfoAddress.Region = i.Region
	j.jsonUserinfoAddress.StreetAddress = i.StreetAddress
}

func (i *Userinfo) UnmmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, i); err != nil {
		return err
	}
	return json.Unmarshal(data, i.claims)
}

type UserInfoRequest struct {
	AccessToken string `schema:"access_token"`
}

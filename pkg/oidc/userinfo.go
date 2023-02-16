package oidc

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/text/language"
)

type UserInfo interface {
	GetSubject() string
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
	GetAddress() UserInfoAddress
	GetClaim(key string) interface{}
	GetClaims() map[string]interface{}
}

type UserInfoProfile interface {
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
	GetPreferredUsername() string
}

type UserInfoEmail interface {
	GetEmail() string
	IsEmailVerified() bool
}

type UserInfoPhone interface {
	GetPhoneNumber() string
	IsPhoneNumberVerified() bool
}

type UserInfoAddress interface {
	GetFormatted() string
	GetStreetAddress() string
	GetLocality() string
	GetRegion() string
	GetPostalCode() string
	GetCountry() string
}

type UserInfoSetter interface {
	UserInfo
	SetSubject(sub string)
	UserInfoProfileSetter
	SetEmail(email string, verified bool)
	SetPhone(phone string, verified bool)
	SetAddress(address UserInfoAddress)
	AppendClaims(key string, values interface{})
}

type UserInfoProfileSetter interface {
	SetName(name string)
	SetGivenName(name string)
	SetFamilyName(name string)
	SetMiddleName(name string)
	SetNickname(name string)
	SetUpdatedAt(date time.Time)
	SetProfile(profile string)
	SetPicture(profile string)
	SetWebsite(website string)
	SetGender(gender Gender)
	SetBirthdate(birthdate string)
	SetZoneinfo(zoneInfo string)
	SetLocale(locale language.Tag)
	SetPreferredUsername(name string)
}

func NewUserInfo() UserInfoSetter {
	return &userinfo{}
}

type userinfo struct {
	Subject string `json:"sub,omitempty"`
	userInfoProfile
	userInfoEmail
	userInfoPhone
	Address UserInfoAddress `json:"address,omitempty"`

	claims map[string]interface{}
}

func (u *userinfo) GetSubject() string {
	return u.Subject
}

func (u *userinfo) GetName() string {
	return u.Name
}

func (u *userinfo) GetGivenName() string {
	return u.GivenName
}

func (u *userinfo) GetFamilyName() string {
	return u.FamilyName
}

func (u *userinfo) GetMiddleName() string {
	return u.MiddleName
}

func (u *userinfo) GetNickname() string {
	return u.Nickname
}

func (u *userinfo) GetProfile() string {
	return u.Profile
}

func (u *userinfo) GetPicture() string {
	return u.Picture
}

func (u *userinfo) GetWebsite() string {
	return u.Website
}

func (u *userinfo) GetGender() Gender {
	return u.Gender
}

func (u *userinfo) GetBirthdate() string {
	return u.Birthdate
}

func (u *userinfo) GetZoneinfo() string {
	return u.Zoneinfo
}

func (u *userinfo) GetLocale() language.Tag {
	return u.Locale
}

func (u *userinfo) GetPreferredUsername() string {
	return u.PreferredUsername
}

func (u *userinfo) GetEmail() string {
	return u.Email
}

func (u *userinfo) IsEmailVerified() bool {
	return bool(u.EmailVerified)
}

func (u *userinfo) GetPhoneNumber() string {
	return u.PhoneNumber
}

func (u *userinfo) IsPhoneNumberVerified() bool {
	return u.PhoneNumberVerified
}

func (u *userinfo) GetAddress() UserInfoAddress {
	if u.Address == nil {
		return &userInfoAddress{}
	}
	return u.Address
}

func (u *userinfo) GetClaim(key string) interface{} {
	return u.claims[key]
}

func (u *userinfo) GetClaims() map[string]interface{} {
	return u.claims
}

func (u *userinfo) SetSubject(sub string) {
	u.Subject = sub
}

func (u *userinfo) SetName(name string) {
	u.Name = name
}

func (u *userinfo) SetGivenName(name string) {
	u.GivenName = name
}

func (u *userinfo) SetFamilyName(name string) {
	u.FamilyName = name
}

func (u *userinfo) SetMiddleName(name string) {
	u.MiddleName = name
}

func (u *userinfo) SetNickname(name string) {
	u.Nickname = name
}

func (u *userinfo) SetUpdatedAt(date time.Time) {
	u.UpdatedAt = Time(date)
}

func (u *userinfo) SetProfile(profile string) {
	u.Profile = profile
}

func (u *userinfo) SetPicture(picture string) {
	u.Picture = picture
}

func (u *userinfo) SetWebsite(website string) {
	u.Website = website
}

func (u *userinfo) SetGender(gender Gender) {
	u.Gender = gender
}

func (u *userinfo) SetBirthdate(birthdate string) {
	u.Birthdate = birthdate
}

func (u *userinfo) SetZoneinfo(zoneInfo string) {
	u.Zoneinfo = zoneInfo
}

func (u *userinfo) SetLocale(locale language.Tag) {
	u.Locale = locale
}

func (u *userinfo) SetPreferredUsername(name string) {
	u.PreferredUsername = name
}

func (u *userinfo) SetEmail(email string, verified bool) {
	u.Email = email
	u.EmailVerified = boolString(verified)
}

func (u *userinfo) SetPhone(phone string, verified bool) {
	u.PhoneNumber = phone
	u.PhoneNumberVerified = verified
}

func (u *userinfo) SetAddress(address UserInfoAddress) {
	u.Address = address
}

func (u *userinfo) AppendClaims(key string, value interface{}) {
	if u.claims == nil {
		u.claims = make(map[string]interface{})
	}
	u.claims[key] = value
}

func (u *userInfoAddress) GetFormatted() string {
	return u.Formatted
}

func (u *userInfoAddress) GetStreetAddress() string {
	return u.StreetAddress
}

func (u *userInfoAddress) GetLocality() string {
	return u.Locality
}

func (u *userInfoAddress) GetRegion() string {
	return u.Region
}

func (u *userInfoAddress) GetPostalCode() string {
	return u.PostalCode
}

func (u *userInfoAddress) GetCountry() string {
	return u.Country
}

type userInfoProfile struct {
	Name              string       `json:"name,omitempty"`
	GivenName         string       `json:"given_name,omitempty"`
	FamilyName        string       `json:"family_name,omitempty"`
	MiddleName        string       `json:"middle_name,omitempty"`
	Nickname          string       `json:"nickname,omitempty"`
	Profile           string       `json:"profile,omitempty"`
	Picture           string       `json:"picture,omitempty"`
	Website           string       `json:"website,omitempty"`
	Gender            Gender       `json:"gender,omitempty"`
	Birthdate         string       `json:"birthdate,omitempty"`
	Zoneinfo          string       `json:"zoneinfo,omitempty"`
	Locale            language.Tag `json:"locale,omitempty"`
	UpdatedAt         Time         `json:"updated_at,omitempty"`
	PreferredUsername string       `json:"preferred_username,omitempty"`
}

type userInfoEmail struct {
	Email string `json:"email,omitempty"`

	// Handle providers that return email_verified as a string
	// https://forums.aws.amazon.com/thread.jspa?messageID=949441&#949441
	// https://discuss.elastic.co/t/openid-error-after-authenticating-against-aws-cognito/206018/11
	EmailVerified boolString `json:"email_verified,omitempty"`
}

type boolString bool

func (bs *boolString) UnmarshalJSON(data []byte) error {
	if string(data) == "true" || string(data) == `"true"` {
		*bs = true
	}

	return nil
}

type userInfoPhone struct {
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
}

type userInfoAddress struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

func NewUserInfoAddress(streetAddress, locality, region, postalCode, country, formatted string) UserInfoAddress {
	return &userInfoAddress{
		StreetAddress: streetAddress,
		Locality:      locality,
		Region:        region,
		PostalCode:    postalCode,
		Country:       country,
		Formatted:     formatted,
	}
}

func (u *userinfo) MarshalJSON() ([]byte, error) {
	type Alias userinfo
	a := &struct {
		*Alias
		Locale    interface{} `json:"locale,omitempty"`
		UpdatedAt int64       `json:"updated_at,omitempty"`
	}{
		Alias: (*Alias)(u),
	}
	if !u.Locale.IsRoot() {
		a.Locale = u.Locale
	}
	if !time.Time(u.UpdatedAt).IsZero() {
		a.UpdatedAt = time.Time(u.UpdatedAt).Unix()
	}

	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	if len(u.claims) == 0 {
		return b, nil
	}

	err = json.Unmarshal(b, &u.claims)
	if err != nil {
		return nil, fmt.Errorf("jws: invalid map of custom claims %v", u.claims)
	}

	return json.Marshal(u.claims)
}

func (u *userinfo) UnmarshalJSON(data []byte) error {
	type Alias userinfo
	a := &struct {
		Address *userInfoAddress `json:"address,omitempty"`
		*Alias
		UpdatedAt int64 `json:"update_at,omitempty"`
	}{
		Alias: (*Alias)(u),
	}
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	if a.Address != nil {
		u.Address = a.Address
	}

	u.UpdatedAt = Time(time.Unix(a.UpdatedAt, 0).UTC())

	if err := json.Unmarshal(data, &u.claims); err != nil {
		return err
	}

	return nil
}

type UserInfoRequest struct {
	AccessToken string `schema:"access_token"`
}

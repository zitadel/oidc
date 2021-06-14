package oidc

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/text/language"
)

type IntrospectionRequest struct {
	Token string `schema:"token"`
}

type ClientAssertionParams struct {
	ClientAssertion     string `schema:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type"`
}

type IntrospectionResponse interface {
	UserInfoSetter
	SetActive(bool)
	IsActive() bool
	SetScopes(scopes []string)
	SetClientID(id string)
}

func NewIntrospectionResponse() IntrospectionResponse {
	return &introspectionResponse{}
}

type introspectionResponse struct {
	Active   bool                `json:"active"`
	Scope    SpaceDelimitedArray `json:"scope,omitempty"`
	ClientID string              `json:"client_id,omitempty"`
	Subject  string              `json:"sub,omitempty"`
	userInfoProfile
	userInfoEmail
	userInfoPhone

	Address UserInfoAddress `json:"address,omitempty"`
	claims  map[string]interface{}
}

func (u *introspectionResponse) IsActive() bool {
	return u.Active
}

func (u *introspectionResponse) SetScopes(scope []string) {
	u.Scope = scope
}

func (u *introspectionResponse) SetClientID(id string) {
	u.ClientID = id
}

func (u *introspectionResponse) GetSubject() string {
	return u.Subject
}

func (u *introspectionResponse) GetName() string {
	return u.Name
}

func (u *introspectionResponse) GetGivenName() string {
	return u.GivenName
}

func (u *introspectionResponse) GetFamilyName() string {
	return u.FamilyName
}

func (u *introspectionResponse) GetMiddleName() string {
	return u.MiddleName
}

func (u *introspectionResponse) GetNickname() string {
	return u.Nickname
}

func (u *introspectionResponse) GetProfile() string {
	return u.Profile
}

func (u *introspectionResponse) GetPicture() string {
	return u.Picture
}

func (u *introspectionResponse) GetWebsite() string {
	return u.Website
}

func (u *introspectionResponse) GetGender() Gender {
	return u.Gender
}

func (u *introspectionResponse) GetBirthdate() string {
	return u.Birthdate
}

func (u *introspectionResponse) GetZoneinfo() string {
	return u.Zoneinfo
}

func (u *introspectionResponse) GetLocale() language.Tag {
	return u.Locale
}

func (u *introspectionResponse) GetPreferredUsername() string {
	return u.PreferredUsername
}

func (u *introspectionResponse) GetEmail() string {
	return u.Email
}

func (u *introspectionResponse) IsEmailVerified() bool {
	return u.EmailVerified
}

func (u *introspectionResponse) GetPhoneNumber() string {
	return u.PhoneNumber
}

func (u *introspectionResponse) IsPhoneNumberVerified() bool {
	return u.PhoneNumberVerified
}

func (u *introspectionResponse) GetAddress() UserInfoAddress {
	return u.Address
}

func (u *introspectionResponse) GetClaim(key string) interface{} {
	return u.claims[key]
}

func (u *introspectionResponse) SetActive(active bool) {
	u.Active = active
}

func (u *introspectionResponse) SetSubject(sub string) {
	u.Subject = sub
}

func (u *introspectionResponse) SetName(name string) {
	u.Name = name
}

func (u *introspectionResponse) SetGivenName(name string) {
	u.GivenName = name
}

func (u *introspectionResponse) SetFamilyName(name string) {
	u.FamilyName = name
}

func (u *introspectionResponse) SetMiddleName(name string) {
	u.MiddleName = name
}

func (u *introspectionResponse) SetNickname(name string) {
	u.Nickname = name
}

func (u *introspectionResponse) SetUpdatedAt(date time.Time) {
	u.UpdatedAt = Time(date)
}

func (u *introspectionResponse) SetProfile(profile string) {
	u.Profile = profile
}

func (u *introspectionResponse) SetPicture(picture string) {
	u.Picture = picture
}

func (u *introspectionResponse) SetWebsite(website string) {
	u.Website = website
}

func (u *introspectionResponse) SetGender(gender Gender) {
	u.Gender = gender
}

func (u *introspectionResponse) SetBirthdate(birthdate string) {
	u.Birthdate = birthdate
}

func (u *introspectionResponse) SetZoneinfo(zoneInfo string) {
	u.Zoneinfo = zoneInfo
}

func (u *introspectionResponse) SetLocale(locale language.Tag) {
	u.Locale = locale
}

func (u *introspectionResponse) SetPreferredUsername(name string) {
	u.PreferredUsername = name
}

func (u *introspectionResponse) SetEmail(email string, verified bool) {
	u.Email = email
	u.EmailVerified = verified
}

func (u *introspectionResponse) SetPhone(phone string, verified bool) {
	u.PhoneNumber = phone
	u.PhoneNumberVerified = verified
}

func (u *introspectionResponse) SetAddress(address UserInfoAddress) {
	u.Address = address
}

func (u *introspectionResponse) AppendClaims(key string, value interface{}) {
	if u.claims == nil {
		u.claims = make(map[string]interface{})
	}
	u.claims[key] = value
}

func (i *introspectionResponse) MarshalJSON() ([]byte, error) {
	type Alias introspectionResponse
	a := &struct {
		*Alias
		Locale    interface{} `json:"locale,omitempty"`
		UpdatedAt int64       `json:"updated_at,omitempty"`
		Username  string      `json:"username,omitempty"`
	}{
		Alias: (*Alias)(i),
	}
	if !i.Locale.IsRoot() {
		a.Locale = i.Locale
	}
	if !time.Time(i.UpdatedAt).IsZero() {
		a.UpdatedAt = time.Time(i.UpdatedAt).Unix()
	}
	a.Username = i.PreferredUsername

	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	if len(i.claims) == 0 {
		return b, nil
	}

	err = json.Unmarshal(b, &i.claims)
	if err != nil {
		return nil, fmt.Errorf("jws: invalid map of custom claims %v", i.claims)
	}

	return json.Marshal(i.claims)
}

func (i *introspectionResponse) UnmarshalJSON(data []byte) error {
	type Alias introspectionResponse
	a := &struct {
		*Alias
		UpdatedAt int64 `json:"update_at,omitempty"`
	}{
		Alias: (*Alias)(i),
	}
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	i.UpdatedAt = Time(time.Unix(a.UpdatedAt, 0).UTC())

	if err := json.Unmarshal(data, &i.claims); err != nil {
		return err
	}

	return nil
}

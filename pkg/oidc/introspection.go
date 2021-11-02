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

func (i *introspectionResponse) IsActive() bool {
	return i.Active
}

func (i *introspectionResponse) SetScopes(scope []string) {
	i.Scope = scope
}

func (i *introspectionResponse) SetClientID(id string) {
	i.ClientID = id
}

func (i *introspectionResponse) GetSubject() string {
	return i.Subject
}

func (i *introspectionResponse) GetName() string {
	return i.Name
}

func (i *introspectionResponse) GetGivenName() string {
	return i.GivenName
}

func (i *introspectionResponse) GetFamilyName() string {
	return i.FamilyName
}

func (i *introspectionResponse) GetMiddleName() string {
	return i.MiddleName
}

func (i *introspectionResponse) GetNickname() string {
	return i.Nickname
}

func (i *introspectionResponse) GetProfile() string {
	return i.Profile
}

func (i *introspectionResponse) GetPicture() string {
	return i.Picture
}

func (i *introspectionResponse) GetWebsite() string {
	return i.Website
}

func (i *introspectionResponse) GetGender() Gender {
	return i.Gender
}

func (i *introspectionResponse) GetBirthdate() string {
	return i.Birthdate
}

func (i *introspectionResponse) GetZoneinfo() string {
	return i.Zoneinfo
}

func (i *introspectionResponse) GetLocale() language.Tag {
	return i.Locale
}

func (i *introspectionResponse) GetPreferredUsername() string {
	return i.PreferredUsername
}

func (i *introspectionResponse) GetEmail() string {
	return i.Email
}

func (i *introspectionResponse) IsEmailVerified() bool {
	return bool(i.EmailVerified)
}

func (i *introspectionResponse) GetPhoneNumber() string {
	return i.PhoneNumber
}

func (i *introspectionResponse) IsPhoneNumberVerified() bool {
	return i.PhoneNumberVerified
}

func (i *introspectionResponse) GetAddress() UserInfoAddress {
	return i.Address
}

func (i *introspectionResponse) GetClaim(key string) interface{} {
	return i.claims[key]
}

func (i *introspectionResponse) SetActive(active bool) {
	i.Active = active
}

func (i *introspectionResponse) SetSubject(sub string) {
	i.Subject = sub
}

func (i *introspectionResponse) SetName(name string) {
	i.Name = name
}

func (i *introspectionResponse) SetGivenName(name string) {
	i.GivenName = name
}

func (i *introspectionResponse) SetFamilyName(name string) {
	i.FamilyName = name
}

func (i *introspectionResponse) SetMiddleName(name string) {
	i.MiddleName = name
}

func (i *introspectionResponse) SetNickname(name string) {
	i.Nickname = name
}

func (i *introspectionResponse) SetUpdatedAt(date time.Time) {
	i.UpdatedAt = Time(date)
}

func (i *introspectionResponse) SetProfile(profile string) {
	i.Profile = profile
}

func (i *introspectionResponse) SetPicture(picture string) {
	i.Picture = picture
}

func (i *introspectionResponse) SetWebsite(website string) {
	i.Website = website
}

func (i *introspectionResponse) SetGender(gender Gender) {
	i.Gender = gender
}

func (i *introspectionResponse) SetBirthdate(birthdate string) {
	i.Birthdate = birthdate
}

func (i *introspectionResponse) SetZoneinfo(zoneInfo string) {
	i.Zoneinfo = zoneInfo
}

func (i *introspectionResponse) SetLocale(locale language.Tag) {
	i.Locale = locale
}

func (i *introspectionResponse) SetPreferredUsername(name string) {
	i.PreferredUsername = name
}

func (i *introspectionResponse) SetEmail(email string, verified bool) {
	i.Email = email
	i.EmailVerified = boolString(verified)
}

func (i *introspectionResponse) SetPhone(phone string, verified bool) {
	i.PhoneNumber = phone
	i.PhoneNumberVerified = verified
}

func (i *introspectionResponse) SetAddress(address UserInfoAddress) {
	i.Address = address
}

func (i *introspectionResponse) AppendClaims(key string, value interface{}) {
	if i.claims == nil {
		i.claims = make(map[string]interface{})
	}
	i.claims[key] = value
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

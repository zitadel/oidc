package oidc

import (
	"fmt"
)

type Bool bool

// UnmarshalJSON handles both standard JSON boolean values and string representations.
// This is necessary because some OIDC providers (notably AWS Cognito) incorrectly return
// boolean fields like email_verified and phone_number_verified as strings ("true"/"false")
// instead of proper JSON booleans, violating the OIDC specification.
//
// The method first attempts standard boolean unmarshaling, and falls back to string
// parsing if that fails, making it compatible with both compliant and non-compliant providers.
//
// Ref:
// - https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
// - https://docs.aws.amazon.com/cognito/latest/developerguide/userinfo-endpoint.html
func (bs *Bool) UnmarshalJSON(data []byte) error {
	s := string(data)
	switch s {
	case "true", `"true"`:
		*bs = true
	case "false", `"false"`:
		*bs = false
	default:
		return fmt.Errorf("cannot unmarshal %s into Bool", s)
	}
	return nil
}

// UserInfo implements OpenID Connect Core 1.0, section 5.1.
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims.
type UserInfo struct {
	Subject string `json:"sub,omitempty"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
	Address *UserInfoAddress `json:"address,omitempty"`

	Claims map[string]any `json:"-"`
}

func (u *UserInfo) AppendClaims(k string, v any) {
	if u.Claims == nil {
		u.Claims = make(map[string]any)
	}

	u.Claims[k] = v
}

// GetAddress is a safe getter that takes
// care of a possible nil value.
func (u *UserInfo) GetAddress() *UserInfoAddress {
	if u.Address == nil {
		return new(UserInfoAddress)
	}
	return u.Address
}

// GetSubject implements [rp.SubjectGetter]
func (u *UserInfo) GetSubject() string {
	return u.Subject
}

type uiAlias UserInfo

func (u *UserInfo) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*uiAlias)(u), u.Claims)
}

func (u *UserInfo) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*uiAlias)(u), &u.Claims)
}

type UserInfoProfile struct {
	Name              string  `json:"name,omitempty"`
	GivenName         string  `json:"given_name,omitempty"`
	FamilyName        string  `json:"family_name,omitempty"`
	MiddleName        string  `json:"middle_name,omitempty"`
	Nickname          string  `json:"nickname,omitempty"`
	Profile           string  `json:"profile,omitempty"`
	Picture           string  `json:"picture,omitempty"`
	Website           string  `json:"website,omitempty"`
	Gender            Gender  `json:"gender,omitempty"`
	Birthdate         string  `json:"birthdate,omitempty"`
	Zoneinfo          string  `json:"zoneinfo,omitempty"`
	Locale            *Locale `json:"locale,omitempty"`
	UpdatedAt         Time    `json:"updated_at,omitempty"`
	PreferredUsername string  `json:"preferred_username,omitempty"`
}

type UserInfoEmail struct {
	Email string `json:"email,omitempty"`

	EmailVerified Bool `json:"email_verified,omitempty"`
}

type UserInfoPhone struct {
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified Bool   `json:"phone_number_verified,omitempty"`
}

type UserInfoAddress struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

type UserInfoRequest struct {
	AccessToken string `schema:"access_token"`
}

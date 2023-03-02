package oidc

import "github.com/muhlemmer/gu"

type IntrospectionRequest struct {
	Token string `schema:"token"`
}

type ClientAssertionParams struct {
	ClientAssertion     string `schema:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type"`
}

type IntrospectionResponse struct {
	Active     bool                `json:"active"`
	Scope      SpaceDelimitedArray `json:"scope,omitempty"`
	ClientID   string              `json:"client_id,omitempty"`
	TokenType  string              `json:"token_type,omitempty"`
	Expiration Time                `json:"exp,omitempty"`
	IssuedAt   Time                `json:"iat,omitempty"`
	NotBefore  Time                `json:"nbf,omitempty"`
	Subject    string              `json:"sub,omitempty"`
	Audience   Audience            `json:"aud,omitempty"`
	Issuer     string              `json:"iss,omitempty"`
	JWTID      string              `json:"jti,omitempty"`
	Username   string              `json:"username,omitempty"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone

	Address *UserInfoAddress `json:"address,omitempty"`
	Claims  map[string]any   `json:"-"`
}

// GetUserInfo copies all user related fields into a new UserInfo.
func (i *IntrospectionResponse) GetUserInfo() *UserInfo {
	return &UserInfo{
		Address:         i.Address,
		Subject:         i.Subject,
		UserInfoProfile: i.UserInfoProfile,
		UserInfoEmail:   i.UserInfoEmail,
		UserInfoPhone:   i.UserInfoPhone,
		Claims:          gu.MapCopy(i.Claims),
	}
}

// SetUserInfo copies all relevant fields from UserInfo
// into the IntroSpectionResponse.
func (i *IntrospectionResponse) SetUserInfo(u *UserInfo) {
	i.Subject = u.Subject
	i.Username = u.PreferredUsername
	i.Address = u.Address
	i.UserInfoProfile = u.UserInfoProfile
	i.UserInfoEmail = u.UserInfoEmail
	i.UserInfoPhone = u.UserInfoPhone
	if i.Claims == nil {
		i.Claims = gu.MapCopy(u.Claims)
	} else {
		gu.MapMerge(u.Claims, i.Claims)
	}
}

// introspectionResponseAlias prevents loops on the JSON methods
type introspectionResponseAlias IntrospectionResponse

func (i *IntrospectionResponse) MarshalJSON() ([]byte, error) {
	if i.Username == "" {
		i.Username = i.PreferredUsername
	}
	return mergeAndMarshalClaims((*introspectionResponseAlias)(i), i.Claims)
}

func (i *IntrospectionResponse) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*introspectionResponseAlias)(i), &i.Claims)
}

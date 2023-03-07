package oidc

import "github.com/muhlemmer/gu"

type IntrospectionRequest struct {
	Token string `schema:"token"`
}

type ClientAssertionParams struct {
	ClientAssertion     string `schema:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type"`
}

// IntrospectionResponse implements RFC 7662, section 2.2 and
// OpenID Connect Core 1.0, section 5.1 (UserInfo).
// https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2.
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims.
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

// SetUserInfo copies all relevant fields from UserInfo
// into the IntroSpectionResponse.
func (i *IntrospectionResponse) SetUserInfo(u *UserInfo) {
	i.Subject = u.Subject
	i.Username = u.PreferredUsername
	i.Address = gu.PtrCopy(u.Address)
	i.UserInfoProfile = u.UserInfoProfile
	i.UserInfoEmail = u.UserInfoEmail
	i.UserInfoPhone = u.UserInfoPhone
	if i.Claims == nil {
		i.Claims = gu.MapCopy(u.Claims)
	} else {
		gu.MapMerge(u.Claims, i.Claims)
	}
}

// GetAddress is a safe getter that takes
// care of a possible nil value.
func (i *IntrospectionResponse) GetAddress() *UserInfoAddress {
	if i.Address == nil {
		return new(UserInfoAddress)
	}
	return i.Address
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

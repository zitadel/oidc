package oidc

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

	// Handle providers that return email_verified as a string
	// https://forums.aws.amazon.com/thread.jspa?messageID=949441&#949441
	// https://discuss.elastic.co/t/openid-error-after-authenticating-against-aws-cognito/206018/11
	EmailVerified Bool `json:"email_verified,omitempty"`
}

type Bool bool

func (bs *Bool) UnmarshalJSON(data []byte) error {
	if string(data) == "true" || string(data) == `"true"` {
		*bs = true
	}

	return nil
}

type UserInfoPhone struct {
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
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

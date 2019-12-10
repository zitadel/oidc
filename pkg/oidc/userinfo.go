package oidc

import (
	"encoding/json"
	"time"
)

type Test struct {
	Userinfo
	Add string `json:"add,omitempty"`
}

type Userinfo struct {
	Subject string
	Address *UserinfoAddress
	UserinfoProfile
	UserinfoEmail
	UserinfoPhone

	claims map[string]interface{}
}

// type UserinfoJSON struct {
// 	Subject       string           `json:"subject,omitempty"`
// 	Address       *UserinfoAddress `json:"address,omitempty"`
// 	Email         string           `json:"email,omitempty"`
// 	EmailVerified bool             `json:"email_verified,omitempty"`
// 	UserinfoProfileJSON
// 	PhoneNumber         string `json:"phone_number,omitempty"`
// 	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`

// 	Claims map[string]interface{} `json:",omitempty"`
// }

// type Claims map[string]interface{}

type UserinfoPhone struct {
	PhoneNumber         string
	PhoneNumberVerified bool
}
type UserinfoProfile struct {
	Name       string
	GivenName  string
	FamilyName string
	MiddleName string
	Nickname   string
	Profile    string
	Picture    string
	Website    string
	Gender     Gender
	Birthdate  string
	Zoneinfo   string
	// Locale            language.Tag
	UpdatedAt         time.Time
	PreferredUsername string
}

// func (i *UserinfoProfile) MarshalJSON() ([]byte, error) {
// 	j := new(UserinfoProfileJSON)
// 	j.UpdatedAt = i.UpdatedAt
// 	return json.Marshal(j)
// }

type UserinfoProfileJSON struct {
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	MiddleName string `json:"middle_name,omitempty"`
	Nickname   string `json:"nickname,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Picture    string `json:"picture,omitempty"`
	Website    string `json:"website,omitempty"`
	Gender     Gender `json:"gender,omitempty"`
	Birthdate  string `json:"birthdate,omitempty"`
	Zoneinfo   string `json:"zoneinfo,omitempty"`
	// Locale     language.Tag `json:"locale,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
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
	claims["updated_at"] = i.UpdatedAt.UTC().Unix()
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
	// claims["email_verified"] = i.EmailVerified
}

func marshalUserinfoPhone(i UserinfoPhone, claims map[string]interface{}) {
	claims["phone_number"] = i.PhoneNumber
	claims["phone_number_verified"] = i.PhoneNumberVerified
}

// func copyClaims(j *Claims, i map[string]interface{}) {
// 	// *j, _ = json.Marshal(i)
// }

// func (p Userinfo) MarshalJSON() ([]byte, error) {
// 	j := new(UserinfoJSON)
// 	j.Subject = p.Subject
// 	b, _ := json.Marshal(j)

// 	var m map[string]json.RawMessage
// 	json.Unmarshal(b, &m)

// 	// Add tags to the map, possibly overriding struct fields
// 	// for k, v := range p.Claims {
// 	// 	// if overriding struct fields is not acceptable:
// 	// 	// if _, ok := m[k]; ok { continue }
// 	// 	b, _ = json.Marshal(v)
// 	// 	ms[k] = json.RawMessage(b)
// 	// }

// 	return json.Marshal(m)
// }

func (i *Userinfo) MarshalJSON() ([]byte, error) {
	claims := i.claims
	if claims == nil {
		claims = make(map[string]interface{})
	}
	// j := new(UserinfoJSON)
	// j.Subject = i.Subject
	// j.Address = i.Address
	// j.Email = i.Email
	// j.EmailVerified = i.EmailVerified
	// j.PhoneNumber = i.PhoneNumber
	// j.PhoneNumberVerified = i.PhoneNumberVerified

	// j.Claims = make(map[string]interface{})
	// claims := map[string]interface{}{
	// 	"sdsa": "jajfi",
	// 	"a23r": "",
	// }

	// j.Claims["Sdsa"] = "sads"
	// j.Claims["3454"] = ""

	// st := new(structpb.Struct)
	// b, _ := json.Marshal(j)
	// err := jsonpb.Unmarshal(bytes.NewReader(b), st)
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Println("st", st)
	// m := new(jsonpb.Marshaler)
	// m.EmitDefaults = false
	// s, _ := m.MarshalToString(st)
	// return []byte(s), nil

	// claims["phone_number"] = i.PhoneNumber
	claims["sub"] = i.Subject
	marshalUserinfoAddress(i.Address, claims)
	marshalUserinfoEmail(i.UserinfoEmail, claims)
	marshalUserinfoPhone(i.UserinfoPhone, claims)
	marshalUserinfoProfile(i.UserinfoProfile, claims)

	// for k, v := range claims {
	// 	j.Claims[k] = v
	// }
	// j.Claims = Claims(m)
	// copyClaims(&j.Claims, i.Claims)
	// j.Claims, _ = json.Marshal(i.Claims)

	// j.Subject = i.Subject

	// if j.Claims == nil {
	// 	j.Claims = make(map[string]interface{})
	// }
	// j.Claims["sub"] = i.Subject
	// if i.Address != nil {
	// 	j.Claims["address"] = i.Address
	// }
	// if i.Email != "" {
	// 	j.Claims["email"] = i.Email
	// }
	// if i.EmailVerified {
	// 	j.Claims["email_verified"] = i.EmailVerified
	// }
	// if i.PhoneNumber != "" {
	// 	j.Claims["phone_number"] = i.PhoneNumber
	// }
	// if i.PhoneNumberVerified {
	// 	j.Claims["phone_number_verified"] = i.PhoneNumberVerified
	// }
	// if !i.UpdatedAt.IsZero() {
	// 	j.Claims["updated_at"] = i.UpdatedAt.UTC().Unix()
	// }
	return json.Marshal(claims)
}

func (i *Userinfo) UnmmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, i); err != nil {
		return err
	}
	return json.Unmarshal(data, i.claims)
}

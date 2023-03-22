package oidc

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"
)

type Audience []string

func (a *Audience) UnmarshalJSON(text []byte) error {
	var i interface{}
	err := json.Unmarshal(text, &i)
	if err != nil {
		return err
	}
	switch aud := i.(type) {
	case []interface{}:
		*a = make([]string, len(aud))
		for i, audience := range aud {
			(*a)[i] = audience.(string)
		}
	case string:
		*a = []string{aud}
	}
	return nil
}

type Display string

func (d *Display) UnmarshalText(text []byte) error {
	display := Display(text)
	switch display {
	case DisplayPage, DisplayPopup, DisplayTouch, DisplayWAP:
		*d = display
	}
	return nil
}

type Gender string

type Locale struct {
	tag language.Tag
}

func NewLocale(tag language.Tag) *Locale {
	return &Locale{tag: tag}
}

func (l *Locale) Tag() language.Tag {
	if l == nil {
		return language.Und
	}

	return l.tag
}

func (l *Locale) String() string {
	return l.Tag().String()
}

func (l *Locale) MarshalJSON() ([]byte, error) {
	tag := l.Tag()
	if tag.IsRoot() {
		return []byte("null"), nil
	}

	return json.Marshal(tag)
}

func (l *Locale) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &l.tag)
}

type Locales []language.Tag

func (l *Locales) UnmarshalText(text []byte) error {
	locales := strings.Split(string(text), " ")
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			*l = append(*l, tag)
		}
	}
	return nil
}

type MaxAge *uint

func NewMaxAge(i uint) MaxAge {
	return &i
}

type SpaceDelimitedArray []string

type Prompt SpaceDelimitedArray

type ResponseType string

type ResponseMode string

func (s SpaceDelimitedArray) Encode() string {
	return strings.Join(s, " ")
}

func (s *SpaceDelimitedArray) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

func (s SpaceDelimitedArray) MarshalText() ([]byte, error) {
	return []byte(s.Encode()), nil
}

func (s SpaceDelimitedArray) MarshalJSON() ([]byte, error) {
	return json.Marshal((s).Encode())
}

func (s *SpaceDelimitedArray) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = strings.Split(str, " ")
	return nil
}

func (s *SpaceDelimitedArray) Scan(src interface{}) error {
	if src == nil {
		*s = nil
		return nil
	}
	switch v := src.(type) {
	case string:
		if len(v) == 0 {
			*s = SpaceDelimitedArray{}
			return nil
		}
		*s = strings.Split(v, " ")
	case []byte:
		if len(v) == 0 {
			*s = SpaceDelimitedArray{}
			return nil
		}
		*s = strings.Split(string(v), " ")
	default:
		return fmt.Errorf("cannot convert %T to SpaceDelimitedArray", src)
	}
	return nil
}

func (s SpaceDelimitedArray) Value() (driver.Value, error) {
	return strings.Join(s, " "), nil
}

// NewEncoder returns a schema Encoder with
// a registered encoder for SpaceDelimitedArray.
func NewEncoder() *schema.Encoder {
	e := schema.NewEncoder()
	e.RegisterEncoder(SpaceDelimitedArray{}, func(value reflect.Value) string {
		return value.Interface().(SpaceDelimitedArray).Encode()
	})
	return e
}

type Time int64

func (ts Time) AsTime() time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(int64(ts), 0)
}

func FromTime(tt time.Time) Time {
	if tt.IsZero() {
		return 0
	}
	return Time(tt.Unix())
}

func NowTime() Time {
	return FromTime(time.Now())
}

func (ts *Time) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("oidc.Time: %w", err)
	}
	switch x := v.(type) {
	case float64:
		*ts = Time(x)
	case string:
		// Compatibility with Auth0:
		// https://github.com/zitadel/oidc/issues/292
		tt, err := time.Parse(time.RFC3339, x)
		if err != nil {
			return fmt.Errorf("oidc.Time: %w", err)
		}
		*ts = FromTime(tt)
	case nil:
		*ts = 0
	default:
		return fmt.Errorf("oidc.Time: unable to parse type %T with value %v", x, x)
	}
	return nil
}

type RequestObject struct {
	Issuer   string   `json:"iss"`
	Audience Audience `json:"aud"`
	AuthRequest
}

func (r *RequestObject) GetIssuer() string {
	return r.Issuer
}

func (*RequestObject) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {}

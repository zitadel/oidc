package oidc

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/muhlemmer/gu"
	"github.com/zitadel/schema"
	"golang.org/x/text/language"
)

type Audience []string

func (a *Audience) UnmarshalJSON(text []byte) error {
	var i any
	err := json.Unmarshal(text, &i)
	if err != nil {
		return err
	}
	switch aud := i.(type) {
	case []any:
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

// UnmarshalJSON implements json.Unmarshaler.
// When [language.ValueError] is encountered, the containing tag will be set
// to an empty value (language "und") and no error will be returned.
// This state can be checked with the `l.Tag().IsRoot()` method.
func (l *Locale) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &l.tag)
	if err == nil {
		return nil
	}

	// catch "well-formed but unknown" errors
	var target language.ValueError
	if errors.As(err, &target) {
		l.tag = language.Tag{}
		return nil
	}
	return err
}

type Locales []language.Tag

// ParseLocales parses a slice of strings into Locales.
// If an entry causes a parse error or is undefined,
// it is ignored and not set to Locales.
func ParseLocales(locales []string) Locales {
	out := make(Locales, 0, len(locales))
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			out = append(out, tag)
		}
	}
	return out
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
// It decodes an unquoted space seperated string into Locales.
// Undefined language tags in the input are ignored and ommited from
// the resulting Locales.
func (l *Locales) UnmarshalText(text []byte) error {
	*l = ParseLocales(
		strings.Split(string(text), " "),
	)
	return nil
}

// UnmarshalJSON implements the [json.Unmarshaler] interface.
// It decodes a json array or a space seperated string into Locales.
// Undefined language tags in the input are ignored and ommited from
// the resulting Locales.
func (l *Locales) UnmarshalJSON(data []byte) error {
	var dst any
	if err := json.Unmarshal(data, &dst); err != nil {
		return fmt.Errorf("oidc locales: %w", err)
	}

	// We catch the posibility of a space seperated string here,
	// because UnmarshalText might have been implicetely called
	// by the json library before we added UnmarshalJSON.
	switch v := dst.(type) {
	case nil:
		*l = nil
	case string:
		*l = ParseLocales(strings.Split(v, " "))
	case []any:
		locales, err := gu.AssertInterfaces[string](v)
		if err != nil {
			return fmt.Errorf("oidc locales: %w", err)
		}
		*l = ParseLocales(locales)
	default:
		return fmt.Errorf("oidc locales: unsupported type: %T", v)
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

func (s SpaceDelimitedArray) String() string {
	return strings.Join(s, " ")
}

func (s *SpaceDelimitedArray) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

func (s SpaceDelimitedArray) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s SpaceDelimitedArray) MarshalJSON() ([]byte, error) {
	return json.Marshal((s).String())
}

func (s *SpaceDelimitedArray) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = strings.Split(str, " ")
	return nil
}

func (s *SpaceDelimitedArray) Scan(src any) error {
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
		return value.Interface().(SpaceDelimitedArray).String()
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

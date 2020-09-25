package oidc

import (
	"encoding/json"
	"strings"
	"time"

	"golang.org/x/text/language"
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

type Locale language.Tag

//{
//	SetLocale(language.Tag)
//	Get() language.Tag
//}
//
//func NewLocale(tag language.Tag) Locale {
//	if tag.IsRoot() {
//		return nil
//	}
//	return &locale{Tag: tag}
//}
//
//type locale struct {
//	language.Tag
//}
//
//func (l *locale) SetLocale(tag language.Tag) {
//	l.Tag = tag
//}
//func (l *locale) Get() language.Tag {
//	return l.Tag
//}

//func (l *locale) MarshalJSON() ([]byte, error) {
//	if l != nil && !l.IsRoot() {
//		return l.MarshalText()
//	}
//	return []byte("null"), nil
//}

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

type Prompt string

type ResponseType string

type Scopes []string

func (s *Scopes) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

type Time time.Time

func (t *Time) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	*t = Time(time.Unix(i, 0).UTC())
	return nil
}

func (t *Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(*t).UTC().Unix())
}

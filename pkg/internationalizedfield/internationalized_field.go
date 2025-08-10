package internationalizedfield

import (
	"golang.org/x/text/language"
)

type languageMap = map[language.Tag]string

// InternationalizedField models a JSON field that is used to represent [Human-Readable Client Metadata].
//
// It references human-readable values and may be represented in multiple languages and scripts.
//
// To specify the languages and scripts, BCP 47 [RFC5646] language tags are added to client metadata member names,
// delimited by a "#" character.
//
// For example, a client could represent its name in English as
//
//	"client_name#en": "My Client"
//
// and its name in Japanese as
//
//	"client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D"
//
// within the same registration request.
//
// [Human-Readable Client Metadata]: https://www.rfc-editor.org/rfc/rfc7591#section-2.2
type InternationalizedField struct {
	FieldName string
	Items     languageMap
}

func New(fieldName string) InternationalizedField {
	return InternationalizedField{
		FieldName: fieldName,
		Items:     make(languageMap),
	}
}

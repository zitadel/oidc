package oidc

import (
	"encoding/json"
	"fmt"
	"golang.org/x/text/language"
	"strings"
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
	Entries   languageMap
}

func NewInternationalizedField(fieldName string) InternationalizedField {
	return InternationalizedField{
		FieldName: fieldName,
		Entries:   make(languageMap),
	}
}

func (i InternationalizedField) insertEntry(key string, value []byte) error {
	var valStr string
	if err := json.Unmarshal(value, &valStr); err != nil {
		return fmt.Errorf("invalid value type for %s, expected string: %e", i.FieldName, err)
	}
	if key == i.FieldName {
		i.Entries[language.Und] = valStr
		return nil
	}
	if !strings.HasPrefix(key, i.FieldName+"#") {
		return fmt.Errorf("invalid format for %s: %q", i.FieldName, key)
	}
	// This is a tagged name, e.g., "client_name#ja-Jpan-JP"
	// Split the key at the first '#' to get the language tag.
	parts := strings.SplitN(key, "#", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for %s: %q", i.FieldName, key)
	}
	langTag, err := language.Parse(parts[1])
	if err != nil {
		return fmt.Errorf("failed to parse language tag for %s: %w", i.FieldName, err)
	}
	i.Entries[langTag] = valStr
	return nil
}

func (i InternationalizedField) exportEntries(res map[string]interface{}) {
	for lang, name := range i.Entries {
		if lang == language.Und {
			res[i.FieldName] = name
		} else {
			res[fmt.Sprintf("%s#%s", i.FieldName, lang)] = name
		}
	}
}

func (i InternationalizedField) GetDefaultEntry() string {
	val := i.GetEntry(language.Und)
	if val == "" {
		for _, v := range i.Entries {
			// return any entry
			return v
		}
	}
	return val
}

func (i InternationalizedField) GetEntry(lang language.Tag) string {
	return i.Entries[lang]
}

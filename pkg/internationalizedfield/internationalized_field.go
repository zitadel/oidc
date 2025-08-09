package internationalizedfield

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
	fieldName string
	Items     languageMap
}

func New(fieldName string) *InternationalizedField {
	return &InternationalizedField{
		fieldName: fieldName,
		Items:     make(languageMap),
	}
}

func (i *InternationalizedField) UnmarshalJSON(data []byte) error {
	i.Items = make(languageMap)

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("could not unmarshal raw data: %w", err)
	}

	for key, value := range raw {
		switch {
		case key == i.fieldName:
			if name, ok := value.(string); ok {
				// This is the default, non-tagged name.
				i.Items[language.Und] = name
			}
		case strings.HasPrefix(key, i.fieldName+"#"):
			if name, ok := value.(string); ok {
				// This is a tagged name, e.g., "client_name#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					if t, err := language.Parse(langTag); err != nil {
						return fmt.Errorf("could not parse language tag %q: %w", langTag, err)
					} else {
						i.Items[t] = name
					}
				}
			}
		}
	}
	return nil
}
func (i InternationalizedField) MarshalJSON() ([]byte, error) {
	res := make(map[string]interface{})
	if len(i.Items) > 0 {
		for lang, name := range i.Items {
			if lang == language.Und {
				res[i.fieldName] = name
			} else {
				res[fmt.Sprintf("%s#%s", i.fieldName, lang)] = name
			}
		}
	}
	return json.Marshal(res)
}

package storage

import (
	"os"
	"path"
	"reflect"
	"testing"

	"golang.org/x/text/language"
)

func TestStoreFromFile(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pathToFile string
		content    string
		want       UserStore
		wantErr    bool
	}{
		{
			name:       "normal user file",
			pathToFile: "userfile.json",
			content: `{
				"id1": {
					"ID":                "id1",
					"EmailVerified":     true,
					"PreferredLanguage": "DE"
				}
			}`,
			want: userStore{map[string]*User{
				"id1": {
					ID:                "id1",
					EmailVerified:     true,
					PreferredLanguage: language.German,
				},
			}},
		},
		{
			name:       "malformed file",
			pathToFile: "whatever",
			content:    "not a json just a text",
			wantErr:    true,
		},
		{
			name:       "not existing file",
			pathToFile: "what/ever/file",
			wantErr:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actualPath := path.Join(t.TempDir(), tc.pathToFile)

			if tc.content != "" && tc.pathToFile != "" {
				if err := os.WriteFile(actualPath, []byte(tc.content), 0666); err != nil {
					t.Fatalf("cannot create file with test content: %q", tc.content)
				}
			}
			result, err := StoreFromFile(actualPath)
			if err != nil && !tc.wantErr {
				t.Errorf("StoreFromFile(%q) returned unexpected error %q", tc.pathToFile, err)
			} else if err == nil && tc.wantErr {
				t.Errorf("StoreFromFile(%q) did not return an expected error", tc.pathToFile)
			}
			if !tc.wantErr && !reflect.DeepEqual(tc.want, result.(userStore)) {
				t.Errorf("expected StoreFromFile(%q) = %v, but got %v",
					tc.pathToFile, tc.want, result)
			}
		})
	}
}

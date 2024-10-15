package config

import (
	"fmt"
	"os"
	"testing"
)

func TestFromEnvVars(t *testing.T) {

	for _, tc := range []struct {
		name     string
		env      map[string]string
		defaults *Config
		want     *Config
	}{
		{
			name: "no vars, no default values",
			env:  map[string]string{},
			want: &Config{},
		},
		{
			name: "no vars, only defaults",
			env:  map[string]string{},
			defaults: &Config{
				Port:         "6666",
				UsersFile:    "/default/user/path",
				RedirectURIs: []string{"re", "direct", "uris"},
				Issuer:       "123",
				DevMode:      true,
			},
			want: &Config{
				Port:         "6666",
				UsersFile:    "/default/user/path",
				RedirectURIs: []string{"re", "direct", "uris"},
				Issuer:       "123",
				DevMode:      true,
			},
		},
		{
			name: "overriding default values",
			env: map[string]string{
				"PORT":          "1234",
				"USERS_FILE":    "/path/to/users",
				"REDIRECT_URIS": "http://redirect/redirect",
				"ISSUER":        "someissuer",
				"DEV_MODE":      "true",
			},
			defaults: &Config{
				Port:         "6666",
				UsersFile:    "/default/user/path",
				RedirectURIs: []string{"re", "direct", "uris"},
				Issuer:       "someissuer",
				DevMode:      false,
			},
			want: &Config{
				Port:         "1234",
				UsersFile:    "/path/to/users",
				RedirectURIs: []string{"http://redirect/redirect"},
				Issuer:       "someissuer",
				DevMode:      true,
			},
		},
		{
			name: "multiple redirect uris",
			env: map[string]string{
				"REDIRECT_URIS": "http://host_1,http://host_2,http://host_3",
			},
			want: &Config{
				RedirectURIs: []string{
					"http://host_1", "http://host_2", "http://host_3",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range tc.env {
				os.Setenv(k, v)
			}
			cfg := FromEnvVars(tc.defaults)
			if fmt.Sprint(cfg) != fmt.Sprint(tc.want) {
				t.Errorf("Expected FromEnvVars()=%v, but got %v", tc.want, cfg)
			}
		})
	}
}

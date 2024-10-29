package config

import (
	"os"
	"strings"
)

const (
	// default port for the http server to run
	DefaultIssuerPort = "9998"
)

type Config struct {
	Port        string
	RedirectURI []string
	UsersFile   string
}

// FromEnvVars loads configuration parameters from environment variables.
// If there is no such variable defined, then use default values.
func FromEnvVars(defaults *Config) *Config {
	if defaults == nil {
		defaults = &Config{}
	}
	cfg := &Config{
		Port:        defaults.Port,
		RedirectURI: defaults.RedirectURI,
		UsersFile:   defaults.UsersFile,
	}
	if value, ok := os.LookupEnv("PORT"); ok {
		cfg.Port = value
	}
	if value, ok := os.LookupEnv("USERS_FILE"); ok {
		cfg.UsersFile = value
	}
	if value, ok := os.LookupEnv("REDIRECT_URI"); ok {
		cfg.RedirectURI = strings.Split(value, ",")
	}
	return cfg
}

package client

import (
	"encoding/json"
	"os"
)

const (
	serviceAccountKey = "serviceaccount"
	applicationKey    = "application"
)

type KeyFile struct {
	Type   string `json:"type"` // serviceaccount or application
	KeyID  string `json:"keyId"`
	Key    string `json:"key"`
	Issuer string `json:"issuer"` // not yet in file

	// serviceaccount
	UserID string `json:"userId"`

	// application
	ClientID string `json:"clientId"`
}

func ConfigFromKeyFile(path string) (*KeyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ConfigFromKeyFileData(data)
}

func ConfigFromKeyFileData(data []byte) (*KeyFile, error) {
	var f KeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

package client

import (
	"encoding/json"
	"io/ioutil"
)

const (
	serviceAccountKey = "serviceaccount"
	applicationKey    = "application"
)

type keyFile struct {
	Type   string `json:"type"` // serviceaccount or application
	KeyID  string `json:"keyId"`
	Key    string `json:"key"`
	Issuer string `json:"issuer"` // not yet in file

	// serviceaccount
	UserID string `json:"userId"`

	// application
	ClientID string `json:"clientId"`
}

func ConfigFromKeyFile(path string) (*keyFile, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ConfigFromKeyFileData(data)
}

func ConfigFromKeyFileData(data []byte) (*keyFile, error) {
	var f keyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

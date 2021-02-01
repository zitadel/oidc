package rp

import (
	"encoding/json"
	"io/ioutil"
)

const (
	serviceAccountKey = "serviceaccount"
	applicationKey    = "application"
)

type keyFile struct {
	Type     string `json:"type"` // serviceaccount or application
	KeyID    string `json:"keyId"`
	Key      string `json:"key"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"clientId"`
	//TokenURL  string `json:"token_uri"`
	//ProjectID string `json:"project_id"`
}

func ConfigFromKeyFile(path string) (*keyFile, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f keyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

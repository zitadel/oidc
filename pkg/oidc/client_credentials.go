package oidc

import "strings"

type clientCredentialsGrantBasic struct {
	grantType string `schema:"grant_type"`
	scope     string `schema:"scope"`
}

type clientCredentialsGrant struct {
	*clientCredentialsGrantBasic
	clientID     string `schema:"client_id"`
	clientSecret string `schema:"client_secret"`
}

//ClientCredentialsGrantBasic creates an oauth2 `Client Credentials` Grant
//sneding client_id and client_secret as basic auth header
func ClientCredentialsGrantBasic(scopes ...string) *clientCredentialsGrantBasic {
	return &clientCredentialsGrantBasic{
		grantType: "client_credentials",
		scope:     strings.Join(scopes, " "),
	}
}

//ClientCredentialsGrantValues creates an oauth2 `Client Credentials` Grant
//sneding client_id and client_secret as form values
func ClientCredentialsGrantValues(clientID, clientSecret string, scopes ...string) *clientCredentialsGrant {
	return &clientCredentialsGrant{
		clientCredentialsGrantBasic: ClientCredentialsGrantBasic(scopes...),
		clientID:                    clientID,
		clientSecret:                clientSecret,
	}
}

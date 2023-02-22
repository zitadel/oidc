package rp

import (
	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func DeviceAuthorization(clientID string, scopes []string, rp RelyingParty) (*oidc.DeviceAuthorizationResponse, error) {
	req := &oidc.DeviceAuthorizationRequest{
		Scopes:   scopes,
		ClientID: clientID,
	}
	return client.CallDeviceAuthorizationEndpoint(req, rp)
}

/*
func DeviceAccessToken() (*oauth2.Token, error) {
	req := &oidc.DeviceAccessTokenRequest{}
}
*/

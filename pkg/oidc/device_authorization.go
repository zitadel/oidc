package oidc

// DeviceAuthorizationRequest implements
// https://www.rfc-editor.org/rfc/rfc8628#section-3.1,
// 3.1 Device Authorization Request.
type DeviceAuthorizationRequest struct {
	Scopes   SpaceDelimitedArray `schema:"scope"`
	ClientID string              `schema:"client_id"`
}

// DeviceAuthorizationResponse implements
// https://www.rfc-editor.org/rfc/rfc8628#section-3.2
// 3.2.  Device Authorization Response.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

// DeviceAccessTokenRequest implements
// https://www.rfc-editor.org/rfc/rfc8628#section-3.4,
// Device Access Token Request.
type DeviceAccessTokenRequest struct {
	GrantType  GrantType `json:"grant_type" schema:"grant_type"`
	DeviceCode string    `json:"device_code" schema:"device_code"`
}

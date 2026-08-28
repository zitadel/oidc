package oidc

import "encoding/json"

// DeviceAuthorizationRequest implements
// https://www.rfc-editor.org/rfc/rfc8628#section-3.1,
// 3.1 Device Authorization Request.
type DeviceAuthorizationRequest struct {
	Scopes   SpaceDelimitedArray `schema:"scope"`
	ClientID string              `schema:"client_id"`

	// Resource indicates the target service(s) or resource(s) at which the requested
	// token is intended to be used, as defined by [RFC 8707]. The parameter may be
	// repeated to request a token that is valid at multiple resources.
	//
	// Each value must be an absolute URI without a fragment component; the op package
	// validates the syntax and rejects invalid values with `invalid_target`.
	//
	// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
	Resource []string `schema:"resource,omitempty"`
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

func (resp *DeviceAuthorizationResponse) UnmarshalJSON(data []byte) error {
	type Alias DeviceAuthorizationResponse
	aux := &struct {
		// workaround misspelling of verification_uri
		// https://stackoverflow.com/q/76696956/5690223
		// https://developers.google.com/identity/protocols/oauth2/limited-input-device?hl=fr#success-response
		VerificationURL string `json:"verification_url"`
		*Alias
	}{
		Alias: (*Alias)(resp),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if resp.VerificationURI == "" {
		resp.VerificationURI = aux.VerificationURL
	}
	return nil
}

// DeviceAccessTokenRequest implements
// https://www.rfc-editor.org/rfc/rfc8628#section-3.4,
// Device Access Token Request.
type DeviceAccessTokenRequest struct {
	GrantType  GrantType `json:"grant_type" schema:"grant_type"`
	DeviceCode string    `json:"device_code" schema:"device_code"`

	// Resource narrows the target service(s) or resource(s) of the issued token,
	// as defined by [RFC 8707, section 2.2]. Every value must be an absolute URI
	// without a fragment component and must have been requested at the device
	// authorization endpoint. If omitted, the resources of the device authorization
	// request are used.
	//
	// [RFC 8707, section 2.2]: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
	Resource []string `json:"resource,omitempty" schema:"resource,omitempty"`
}

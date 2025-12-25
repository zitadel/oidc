package oidc

// BackchannelAuthenticationRequest represents a request to the backchannel authentication endpoint
// as defined in the CIBA (Client Initiated Backchannel Authentication) specification.
//
// Note: Client authentication (client_secret, client_assertion) is handled separately
// via HTTP Basic Auth, POST body, or JWT assertion - NOT in this struct.
type BackchannelAuthenticationRequest struct {
	// Scopes is a space-delimited list of requested scopes
	Scopes SpaceDelimitedArray `schema:"scope"`

	// LoginHint is a hint to the authorization server about the login identifier the end-user might use to log in
	LoginHint string `schema:"login_hint"`

	// BindingMessage is a human-readable identifier or message intended to be displayed on both the
	// consumption device and the authentication device to ensure the user is approving the correct request.
	// Max 20 characters per CIBA spec Section 7.1
	BindingMessage string `schema:"binding_message,omitempty"`

	// UserCode is a secret code used to authorize the backchannel authentication request
	UserCode string `schema:"user_code,omitempty"`

	// RequestedExpiry is a positive integer allowing the client to request the expires_in value for the auth_req_id
	// the server will return (in seconds)
	RequestedExpiry int `schema:"requested_expiry,omitempty"`

	// ClientID is the OAuth 2.0 Client Identifier (for public clients)
	ClientID string `schema:"client_id"`

	// Future fields (not implemented in v1):
	// IDTokenHint        string              `schema:"id_token_hint,omitempty"`
	// LoginHintToken     string              `schema:"login_hint_token,omitempty"`
	// ClientNotificationToken string         `schema:"client_notification_token,omitempty"`
	// ACRValues          SpaceDelimitedArray `schema:"acr_values,omitempty"`
}

// BackchannelAuthenticationResponse represents the successful response from the backchannel authentication endpoint
// as defined in CIBA spec Section 7.2
type BackchannelAuthenticationResponse struct {
	// AuthReqID is a unique identifier to identify the authentication request made by the client
	AuthReqID string `json:"auth_req_id"`

	// ExpiresIn is the expiration time of the auth_req_id in seconds
	ExpiresIn int `json:"expires_in"`

	// Interval is the minimum amount of time in seconds that the client should wait between polling requests
	// to the token endpoint. Only required for poll mode.
	Interval int `json:"interval,omitempty"`
}

// BackchannelTokenRequest represents a token request using the CIBA grant type
// The client polls the token endpoint with the auth_req_id until the authentication is complete
type BackchannelTokenRequest struct {
	// GrantType must be urn:openid:params:grant-type:ciba
	GrantType GrantType `schema:"grant_type"`

	// AuthReqID is the unique identifier received from the backchannel authentication endpoint
	AuthReqID string `schema:"auth_req_id"`
}

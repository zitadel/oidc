package oidc

// PARRequest implements

// https://datatracker.ietf.org/doc/html/rfc9126#name-request,

// 2.1  Request.

type PARRequest AuthRequest

// PARResponse implements

// https://www.rfc-editor.org/rfc/rfc8628#section-3.2

// 3.2.  Successful Response.

type PARResponse struct {
	RequestURI string `json:"request_uri"`

	ExpiresIn int `json:"expires_in"`
}

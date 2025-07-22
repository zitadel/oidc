package oidc

// ClientRegistrationRequest implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.1,
// 3.1 Client Registration Request.
type ClientRegistrationRequest struct {
	// TODO
}

// ClientInformationResponse implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1,
// 3.2.1. Client Information Response and
// https://www.rfc-editor.org/rfc/rfc7592.html#section-3
// 3. Client Information Response.
type ClientInformationResponse struct {
	// TODO
}

// ClientReadRequest implements
// https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1,
// 2.1 Client Read Request.
type ClientReadRequest struct {
	// TODO
	ClientID string `schema:"client_id"`
}

// ClientUpdateRequest implements
// https://www.rfc-editor.org/rfc/rfc7592.html#section-2.2,
// 2.2 Client Update Request.
type ClientUpdateRequest struct {
	// TODO
	ClientID string `schema:"client_id"`
}

// ClientDeleteRequest implements
// https://www.rfc-editor.org/rfc/rfc7592.html#section-2.3,
// 2.3 Client Delete Request.
type ClientDeleteRequest struct {
	// TODO
	ClientID string `schema:"client_id"`
}

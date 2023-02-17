package oidc

// Some expirimental stuff, no sure yet if it can be used
// or deleted before final PR.

/*
// CustomClaims allows the joining of any type
// with Registered fields and a map of custom Claims.
type CustomClaims[R any] struct {
	Registered R
	Claims     map[string]any
}

func (c *CustomClaims[_]) AppendClaims(k string, v any) {
	if c.Claims == nil {
		c.Claims = make(map[string]any)
	}
	c.Claims[k] = v
}

// MarshalJSON implements the json.Marshaller interface.
// The Registered and Claims map are merged into a
// single JSON object. Registered fields overwrite
// custom Claims.
func (c *CustomClaims[_]) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims(&c.Registered, c.Claims)
}

// UnmashalJSON implements the json.Unmarshaller interface.
// Matching values from the JSON document are set in Registered.
// The map Claims will contain all claims from the JSON document.
func (c *CustomClaims[_]) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, &c.Registered, &c.Claims)
}

// CustomTokenClaims allows the joining of a Claims
// type with registered fields and a map of custom Claims.
// CustomTokenClaims implements the Claims interface,
// and any type that embeds TokenClaims can be used as
// type argument.
type CustomTokenClaims[TC Claims] struct {
	Registered TC
	Claims     map[string]any
}

func (c *CustomTokenClaims[_]) AppendClaims(k string, v any) {
	if c.Claims == nil {
		c.Claims = make(map[string]any)
	}
	c.Claims[k] = v
}

// MarshalJSON implements the json.Marshaller interface.
// The Registered and Claims map are merged into a
// single JSON object. Registered fields overwrite
// custom Claims.
func (c *CustomTokenClaims[_]) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims(&c.Registered, c.Claims)
}

// UnmashalJSON implements the json.Unmarshaller interface.
// Matching values from the JSON document are set in Registered.
// The map Claims will contain all claims from the JSON document.
func (c *CustomTokenClaims[_]) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, &c.Registered, &c.Claims)
}

func (c *CustomTokenClaims[_]) GetIssuer() string        { return c.Registered.GetIssuer() }
func (c *CustomTokenClaims[_]) GetSubject() string       { return c.Registered.GetSubject() }
func (c *CustomTokenClaims[_]) GetAudience() []string    { return c.Registered.GetAudience() }
func (c *CustomTokenClaims[_]) GetExpiration() time.Time { return c.Registered.GetExpiration() }
func (c *CustomTokenClaims[_]) GetIssuedAt() time.Time   { return c.Registered.GetIssuedAt() }
func (c *CustomTokenClaims[_]) GetNonce() string         { return c.Registered.GetNonce() }
func (c *CustomTokenClaims[_]) GetAuthTime() time.Time   { return c.Registered.GetAuthTime() }
func (c *CustomTokenClaims[_]) GetAuthorizedParty() string {
	return c.Registered.GetAuthorizedParty()
}
func (c *CustomTokenClaims[_]) GetAuthenticationContextClassReference() string {
	return c.Registered.GetAuthenticationContextClassReference()
}
func (c *CustomTokenClaims[_]) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {
	c.Registered.SetSignatureAlgorithm(algorithm)
}
*/

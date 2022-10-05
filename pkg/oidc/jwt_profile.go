package oidc

type JWTProfileGrantRequest struct {
	Assertion string              `schema:"assertion"`
	Scope     SpaceDelimitedArray `schema:"scope"`
	GrantType GrantType           `schema:"grant_type"`
}

// NewJWTProfileGrantRequest creates an oauth2 `JSON Web Token (JWT) Profile` Grant
//`urn:ietf:params:oauth:grant-type:jwt-bearer`
// sending a self-signed jwt as assertion
func NewJWTProfileGrantRequest(assertion string, scopes ...string) *JWTProfileGrantRequest {
	return &JWTProfileGrantRequest{
		GrantType: GrantTypeBearer,
		Assertion: assertion,
		Scope:     scopes,
	}
}

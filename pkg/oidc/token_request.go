package oidc

import (
	"time"

	"gopkg.in/square/go-jose.v2"
)

const (
	//GrantTypeCode defines the grant_type `authorization_code` used for the Token Request in the Authorization Code Flow
	GrantTypeCode GrantType = "authorization_code"
	//GrantTypeBearer define the grant_type `urn:ietf:params:oauth:grant-type:jwt-bearer` used for the JWT Authorization Grant
	GrantTypeBearer GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type GrantType string

type TokenRequest interface {
	// GrantType GrantType `schema:"grant_type"`
	GrantType() GrantType
}

type TokenRequestType GrantType

type AccessTokenRequest struct {
	Code         string `schema:"code"`
	RedirectURI  string `schema:"redirect_uri"`
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
	CodeVerifier string `schema:"code_verifier"`
}

func (a *AccessTokenRequest) GrantType() GrantType {
	return GrantTypeCode
}

type JWTTokenRequest struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Scopes    Scopes   `json:"-"`
	Audience  Audience `json:"aud"`
	IssuedAt  Time     `json:"iat"`
	ExpiresAt Time     `json:"exp"`
}

func (j *JWTTokenRequest) GetClientID() string {
	return j.Subject
}

func (j *JWTTokenRequest) GetSubject() string {
	return j.Subject
}

func (j *JWTTokenRequest) GetScopes() []string {
	return j.Scopes
}

func (j *JWTTokenRequest) GetIssuer() string {
	return j.Issuer
}

func (j *JWTTokenRequest) GetAudience() []string {
	return j.Audience
}

func (j *JWTTokenRequest) GetExpiration() time.Time {
	return time.Time(j.ExpiresAt)
}

func (j *JWTTokenRequest) GetIssuedAt() time.Time {
	return time.Time(j.IssuedAt)
}

func (j *JWTTokenRequest) GetNonce() string {
	return ""
}

func (j *JWTTokenRequest) GetAuthenticationContextClassReference() string {
	return ""
}

func (j *JWTTokenRequest) GetAuthTime() time.Time {
	return time.Time{}
}

func (j *JWTTokenRequest) GetAuthorizedParty() string {
	return ""
}

func (j *JWTTokenRequest) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {}

type TokenExchangeRequest struct {
	subjectToken       string   `schema:"subject_token"`
	subjectTokenType   string   `schema:"subject_token_type"`
	actorToken         string   `schema:"actor_token"`
	actorTokenType     string   `schema:"actor_token_type"`
	resource           []string `schema:"resource"`
	audience           Audience `schema:"audience"`
	Scope              Scopes   `schema:"scope"`
	requestedTokenType string   `schema:"requested_token_type"`
}

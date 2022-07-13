package oidc

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const (
	//GrantTypeCode defines the grant_type `authorization_code` used for the Token Request in the Authorization Code Flow
	GrantTypeCode GrantType = "authorization_code"

	//GrantTypeRefreshToken defines the grant_type `refresh_token` used for the Token Request in the Refresh Token Flow
	GrantTypeRefreshToken GrantType = "refresh_token"

	//GrantTypeClientCredentials defines the grant_type `client_credentials` used for the Token Request in the Client Credentials Token Flow
	GrantTypeClientCredentials GrantType = "client_credentials"

	//GrantTypeBearer defines the grant_type `urn:ietf:params:oauth:grant-type:jwt-bearer` used for the JWT Authorization Grant
	GrantTypeBearer GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	//GrantTypeTokenExchange defines the grant_type `urn:ietf:params:oauth:grant-type:token-exchange` used for the OAuth Token Exchange Grant
	GrantTypeTokenExchange GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	//GrantTypeImplicit defines the grant type `implicit` used for implicit flows that skip the generation and exchange of an Authorization Code
	GrantTypeImplicit GrantType = "implicit"

	//ClientAssertionTypeJWTAssertion defines the client_assertion_type `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
	//used for the OAuth JWT Profile Client Authentication
	ClientAssertionTypeJWTAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

var AllGrantTypes = []GrantType{
	GrantTypeCode, GrantTypeRefreshToken, GrantTypeClientCredentials,
	GrantTypeBearer, GrantTypeTokenExchange, GrantTypeImplicit,
	ClientAssertionTypeJWTAssertion}

type GrantType string

type TokenRequest interface {
	// GrantType GrantType `schema:"grant_type"`
	GrantType() GrantType
}

type TokenRequestType GrantType

type AccessTokenRequest struct {
	Code                string `schema:"code"`
	RedirectURI         string `schema:"redirect_uri"`
	ClientID            string `schema:"client_id"`
	ClientSecret        string `schema:"client_secret"`
	CodeVerifier        string `schema:"code_verifier"`
	ClientAssertion     string `schema:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type"`
}

func (a *AccessTokenRequest) GrantType() GrantType {
	return GrantTypeCode
}

//SetClientID implements op.AuthenticatedTokenRequest
func (a *AccessTokenRequest) SetClientID(clientID string) {
	a.ClientID = clientID
}

//SetClientSecret implements op.AuthenticatedTokenRequest
func (a *AccessTokenRequest) SetClientSecret(clientSecret string) {
	a.ClientSecret = clientSecret
}

type RefreshTokenRequest struct {
	RefreshToken        string              `schema:"refresh_token"`
	Scopes              SpaceDelimitedArray `schema:"scope"`
	ClientID            string              `schema:"client_id"`
	ClientSecret        string              `schema:"client_secret"`
	ClientAssertion     string              `schema:"client_assertion"`
	ClientAssertionType string              `schema:"client_assertion_type"`
}

func (a *RefreshTokenRequest) GrantType() GrantType {
	return GrantTypeRefreshToken
}

//SetClientID implements op.AuthenticatedTokenRequest
func (a *RefreshTokenRequest) SetClientID(clientID string) {
	a.ClientID = clientID
}

//SetClientSecret implements op.AuthenticatedTokenRequest
func (a *RefreshTokenRequest) SetClientSecret(clientSecret string) {
	a.ClientSecret = clientSecret
}

type JWTTokenRequest struct {
	Issuer    string              `json:"iss"`
	Subject   string              `json:"sub"`
	Scopes    SpaceDelimitedArray `json:"-"`
	Audience  Audience            `json:"aud"`
	IssuedAt  Time                `json:"iat"`
	ExpiresAt Time                `json:"exp"`

	private map[string]interface{}
}

func (j *JWTTokenRequest) MarshalJSON() ([]byte, error) {
	type Alias JWTTokenRequest
	a := (*Alias)(j)

	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	if len(j.private) == 0 {
		return b, nil
	}

	err = json.Unmarshal(b, &j.private)
	if err != nil {
		return nil, fmt.Errorf("jws: invalid map of custom claims %v", j.private)
	}

	return json.Marshal(j.private)
}

func (j *JWTTokenRequest) UnmarshalJSON(data []byte) error {
	type Alias JWTTokenRequest
	a := (*Alias)(j)

	err := json.Unmarshal(data, a)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &j.private)
	if err != nil {
		return err
	}

	return nil
}

func (j *JWTTokenRequest) GetCustomClaim(key string) interface{} {
	return j.private[key]
}

//GetIssuer implements the Claims interface
func (j *JWTTokenRequest) GetIssuer() string {
	return j.Issuer
}

//GetAudience implements the Claims and TokenRequest interfaces
func (j *JWTTokenRequest) GetAudience() []string {
	return j.Audience
}

//GetExpiration implements the Claims interface
func (j *JWTTokenRequest) GetExpiration() time.Time {
	return time.Time(j.ExpiresAt)
}

//GetIssuedAt implements the Claims interface
func (j *JWTTokenRequest) GetIssuedAt() time.Time {
	return time.Time(j.IssuedAt)
}

//GetNonce implements the Claims interface
func (j *JWTTokenRequest) GetNonce() string {
	return ""
}

//GetAuthenticationContextClassReference implements the Claims interface
func (j *JWTTokenRequest) GetAuthenticationContextClassReference() string {
	return ""
}

//GetAuthTime implements the Claims interface
func (j *JWTTokenRequest) GetAuthTime() time.Time {
	return time.Time{}
}

//GetAuthorizedParty implements the Claims interface
func (j *JWTTokenRequest) GetAuthorizedParty() string {
	return ""
}

//SetSignatureAlgorithm implements the Claims interface
func (j *JWTTokenRequest) SetSignatureAlgorithm(_ jose.SignatureAlgorithm) {}

//GetSubject implements the TokenRequest interface
func (j *JWTTokenRequest) GetSubject() string {
	return j.Subject
}

//GetScopes implements the TokenRequest interface
func (j *JWTTokenRequest) GetScopes() []string {
	return j.Scopes
}

type TokenExchangeRequest struct {
	subjectToken       string              `schema:"subject_token"`
	subjectTokenType   string              `schema:"subject_token_type"`
	actorToken         string              `schema:"actor_token"`
	actorTokenType     string              `schema:"actor_token_type"`
	resource           []string            `schema:"resource"`
	audience           Audience            `schema:"audience"`
	Scope              SpaceDelimitedArray `schema:"scope"`
	requestedTokenType string              `schema:"requested_token_type"`
}

type ClientCredentialsRequest struct {
	GrantType    GrantType           `schema:"grant_type"`
	Scope        SpaceDelimitedArray `schema:"scope"`
	ClientID     string              `schema:"client_id"`
	ClientSecret string              `schema:"client_secret"`
}

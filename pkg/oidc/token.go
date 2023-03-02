package oidc

import (
	"encoding/json"
	"os"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/v2/pkg/crypto"
)

const (
	// BearerToken defines the token_type `Bearer`, which is returned in a successful token response
	BearerToken = "Bearer"

	PrefixBearer = BearerToken + " "
)

type Tokens struct {
	*oauth2.Token
	IDTokenClaims *IDTokenClaims
	IDToken       string
}

// TokenClaims contains the base Claims used all tokens.
// It implements OpenID Connect Core 1.0, section 2.
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// And RFC 9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens,
// section 2.2. https://datatracker.ietf.org/doc/html/rfc9068#name-data-structure
//
// TokenClaims implements the Claims interface,
// and can be used to extend larger claim types by embedding.
type TokenClaims struct {
	Issuer                              string   `json:"iss,omitempty"`
	Subject                             string   `json:"sub,omitempty"`
	Audience                            Audience `json:"aud,omitempty"`
	Expiration                          Time     `json:"exp,omitempty"`
	IssuedAt                            Time     `json:"iat,omitempty"`
	AuthTime                            Time     `json:"auth_time,omitempty"`
	Nonce                               string   `json:"nonce,omitempty"`
	AuthenticationContextClassReference string   `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string `json:"amr,omitempty"`
	AuthorizedParty                     string   `json:"azp,omitempty"`
	ClientID                            string   `json:"client_id,omitempty"`
	JWTID                               string   `json:"jti,omitempty"`

	// Additional information set by this framework
	SignatureAlg jose.SignatureAlgorithm `json:"-"`
}

func (c *TokenClaims) GetIssuer() string                              { return c.Issuer }
func (c *TokenClaims) GetSubject() string                             { return c.Subject }
func (c *TokenClaims) GetAudience() []string                          { return c.Audience }
func (c *TokenClaims) GetExpiration() time.Time                       { return c.Expiration.AsTime() }
func (c *TokenClaims) GetIssuedAt() time.Time                         { return c.IssuedAt.AsTime() }
func (c *TokenClaims) GetNonce() string                               { return c.Nonce }
func (c *TokenClaims) GetAuthTime() time.Time                         { return c.AuthTime.AsTime() }
func (c *TokenClaims) GetAuthorizedParty() string                     { return c.AuthorizedParty }
func (c *TokenClaims) GetSignatureAlgorithm() jose.SignatureAlgorithm { return c.SignatureAlg }
func (c *TokenClaims) GetAuthenticationContextClassReference() string {
	return c.AuthenticationContextClassReference
}
func (c *TokenClaims) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {
	c.SignatureAlg = algorithm
}

type AccessTokenClaims struct {
	TokenClaims
	NotBefore            Time     `json:"nbf,omitempty"`
	CodeHash             string   `json:"c_hash,omitempty"`
	SessionID            string   `json:"sid,omitempty"`
	Scopes               []string `json:"scope,omitempty"`
	AccessTokenUseNumber int      `json:"at_use_nbr,omitempty"`

	Claims map[string]any `json:"-"`
}

func NewAccessTokenClaims(issuer, subject string, audience []string, expiration time.Time, jwtid, clientID string, skew time.Duration) *AccessTokenClaims {
	now := time.Now().UTC().Add(-skew)
	if len(audience) == 0 {
		audience = append(audience, clientID)
	}
	return &AccessTokenClaims{
		TokenClaims: TokenClaims{
			Issuer:     issuer,
			Subject:    subject,
			Audience:   audience,
			Expiration: FromTime(expiration),
			IssuedAt:   FromTime(now),
			JWTID:      jwtid,
		},
		NotBefore: FromTime(now),
	}
}

type atcAlias AccessTokenClaims

func (a *AccessTokenClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*atcAlias)(a), a.Claims)
}

func (a *AccessTokenClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*atcAlias)(a), &a.Claims)
}

type IDTokenClaims struct {
	TokenClaims
	NotBefore       Time   `json:"nbf,omitempty"`
	AccessTokenHash string `json:"at_hash,omitempty"`
	CodeHash        string `json:"c_hash,omitempty"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
	Address *UserInfoAddress `json:"address,omitempty"`
	Claims  map[string]any   `json:"-"`
}

// GetAccessTokenHash implements the IDTokenClaims interface
func (t *IDTokenClaims) GetAccessTokenHash() string {
	return t.AccessTokenHash
}

func (t *IDTokenClaims) SetUserInfo(i *UserInfo) {
	t.Subject = i.Subject
	t.UserInfoProfile = i.UserInfoProfile
	t.UserInfoEmail = i.UserInfoEmail
	t.UserInfoPhone = i.UserInfoPhone
	t.Address = i.Address
}

func NewIDTokenClaims(issuer, subject string, audience []string, expiration, authTime time.Time, nonce string, acr string, amr []string, clientID string, skew time.Duration) *IDTokenClaims {
	audience = AppendClientIDToAudience(clientID, audience)
	return &IDTokenClaims{
		TokenClaims: TokenClaims{
			Issuer:                              issuer,
			Subject:                             subject,
			Audience:                            audience,
			Expiration:                          FromTime(expiration),
			IssuedAt:                            FromTime(time.Now().Add(-skew)),
			AuthTime:                            FromTime(authTime.Add(-skew)),
			Nonce:                               nonce,
			AuthenticationContextClassReference: acr,
			AuthenticationMethodsReferences:     amr,
			AuthorizedParty:                     clientID,
		},
	}
}

type itcAlias IDTokenClaims

func (i *IDTokenClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*itcAlias)(i), i.Claims)
}

func (i *IDTokenClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*itcAlias)(i), &i.Claims)
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty" schema:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty" schema:"refresh_token,omitempty"`
	ExpiresIn    uint64 `json:"expires_in,omitempty" schema:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty" schema:"id_token,omitempty"`
	State        string `json:"state,omitempty" schema:"state,omitempty"`
}

type JWTProfileAssertionClaims struct {
	PrivateKeyID string   `json:"-"`
	PrivateKey   []byte   `json:"-"`
	Issuer       string   `json:"iss"`
	Subject      string   `json:"sub"`
	Audience     Audience `json:"aud"`
	Expiration   Time     `json:"exp"`
	IssuedAt     Time     `json:"iat"`

	Claims map[string]interface{} `json:"-"`
}

type jpaAlias JWTProfileAssertionClaims

func (j *JWTProfileAssertionClaims) MarshalJSON() ([]byte, error) {
	return mergeAndMarshalClaims((*jpaAlias)(j), j.Claims)
}

func (j *JWTProfileAssertionClaims) UnmarshalJSON(data []byte) error {
	return unmarshalJSONMulti(data, (*jpaAlias)(j), &j.Claims)
}

func NewJWTProfileAssertionFromKeyJSON(filename string, audience []string, opts ...AssertionOption) (*JWTProfileAssertionClaims, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewJWTProfileAssertionFromFileData(data, audience, opts...)
}

func NewJWTProfileAssertionStringFromFileData(data []byte, audience []string, opts ...AssertionOption) (string, error) {
	keyData := new(struct {
		KeyID  string `json:"keyId"`
		Key    string `json:"key"`
		UserID string `json:"userId"`
	})
	err := json.Unmarshal(data, keyData)
	if err != nil {
		return "", err
	}
	return GenerateJWTProfileToken(NewJWTProfileAssertion(keyData.UserID, keyData.KeyID, audience, []byte(keyData.Key), opts...))
}

func JWTProfileDelegatedSubject(sub string) func(*JWTProfileAssertionClaims) {
	return func(j *JWTProfileAssertionClaims) {
		j.Subject = sub
	}
}

func JWTProfileCustomClaim(key string, value interface{}) func(*JWTProfileAssertionClaims) {
	return func(j *JWTProfileAssertionClaims) {
		j.Claims[key] = value
	}
}

func NewJWTProfileAssertionFromFileData(data []byte, audience []string, opts ...AssertionOption) (*JWTProfileAssertionClaims, error) {
	keyData := new(struct {
		KeyID  string `json:"keyId"`
		Key    string `json:"key"`
		UserID string `json:"userId"`
	})
	err := json.Unmarshal(data, keyData)
	if err != nil {
		return nil, err
	}
	return NewJWTProfileAssertion(keyData.UserID, keyData.KeyID, audience, []byte(keyData.Key), opts...), nil
}

type AssertionOption func(*JWTProfileAssertionClaims)

func NewJWTProfileAssertion(userID, keyID string, audience []string, key []byte, opts ...AssertionOption) *JWTProfileAssertionClaims {
	j := &JWTProfileAssertionClaims{
		PrivateKey:   key,
		PrivateKeyID: keyID,
		Issuer:       userID,
		Subject:      userID,
		IssuedAt:     FromTime(time.Now().UTC()),
		Expiration:   FromTime(time.Now().Add(1 * time.Hour).UTC()),
		Audience:     audience,
		Claims:       make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(j)
	}

	return j
}

func ClaimHash(claim string, sigAlgorithm jose.SignatureAlgorithm) (string, error) {
	hash, err := crypto.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}

	return crypto.HashString(hash, claim, true), nil
}

func AppendClientIDToAudience(clientID string, audience []string) []string {
	for _, aud := range audience {
		if aud == clientID {
			return audience
		}
	}
	return append(audience, clientID)
}

func GenerateJWTProfileToken(assertion *JWTProfileAssertionClaims) (string, error) {
	privateKey, err := crypto.BytesToPrivateKey(assertion.PrivateKey)
	if err != nil {
		return "", err
	}
	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       &jose.JSONWebKey{Key: privateKey, KeyID: assertion.PrivateKeyID},
	}
	signer, err := jose.NewSigner(key, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}

	marshalledAssertion, err := json.Marshal(assertion)
	if err != nil {
		return "", err
	}
	signedAssertion, err := signer.Sign(marshalledAssertion)
	if err != nil {
		return "", err
	}
	return signedAssertion.CompactSerialize()
}

type TokenExchangeResponse struct {
	AccessToken     string              `json:"access_token"` // Can be access token or ID token
	IssuedTokenType TokenType           `json:"issued_token_type"`
	TokenType       string              `json:"token_type"`
	ExpiresIn       uint64              `json:"expires_in,omitempty"`
	Scopes          SpaceDelimitedArray `json:"scope,omitempty"`
	RefreshToken    string              `json:"refresh_token,omitempty"`
}

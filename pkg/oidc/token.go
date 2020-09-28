package oidc

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/utils"
)

const (
	//BearerToken defines the token_type `Bearer`, which is returned in a successful token response
	BearerToken = "Bearer"
)

type Tokens struct {
	*oauth2.Token
	IDTokenClaims IDTokenClaims
	IDToken       string
}

type AccessTokenClaims interface {
	Claims
}

type IDTokenClaims interface {
	Claims
	GetNotBefore() time.Time
	GetJWTID() string
	GetAccessTokenHash() string
	GetCodeHash() string
	GetAuthenticationMethodsReferences() []string
	GetClientID() string
	GetSignatureAlgorithm() jose.SignatureAlgorithm
	SetAccessTokenHash(hash string)
	SetUserinfo(userinfo UserInfoSetter)
	SetCodeHash(hash string)
	UserInfo
}

type accessTokenClaims struct {
	Issuer                              string
	Subject                             string
	Audience                            Audience
	Expiration                          Time
	IssuedAt                            Time
	NotBefore                           Time
	JWTID                               string
	AuthorizedParty                     string
	Nonce                               string
	AuthTime                            Time
	CodeHash                            string
	AuthenticationContextClassReference string
	AuthenticationMethodsReferences     []string
	SessionID                           string
	Scopes                              []string
	ClientID                            string
	AccessTokenUseNumber                int

	signatureAlg jose.SignatureAlgorithm
}

func (a accessTokenClaims) GetIssuer() string {
	return a.Issuer
}

func (a accessTokenClaims) GetAudience() []string {
	return a.Audience
}

func (a accessTokenClaims) GetExpiration() time.Time {
	return time.Time(a.Expiration)
}

func (a accessTokenClaims) GetIssuedAt() time.Time {
	return time.Time(a.IssuedAt)
}

func (a accessTokenClaims) GetNonce() string {
	return a.Nonce
}

func (a accessTokenClaims) GetAuthenticationContextClassReference() string {
	return a.AuthenticationContextClassReference
}

func (a accessTokenClaims) GetAuthTime() time.Time {
	return time.Time(a.AuthTime)
}

func (a accessTokenClaims) GetAuthorizedParty() string {
	return a.AuthorizedParty
}

func (a accessTokenClaims) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {
	a.signatureAlg = algorithm
}

func NewAccessTokenClaims(issuer, subject string, audience []string, expiration time.Time, id string) AccessTokenClaims {
	now := time.Now().UTC()
	return &accessTokenClaims{
		Issuer:     issuer,
		Subject:    subject,
		Audience:   audience,
		Expiration: Time(expiration),
		IssuedAt:   Time(now),
		NotBefore:  Time(now),
		JWTID:      id,
	}
}

type idTokenClaims struct {
	Issuer                              string   `json:"iss,omitempty"`
	Audience                            Audience `json:"aud,omitempty"`
	Expiration                          Time     `json:"exp,omitempty"`
	NotBefore                           Time     `json:"nbf,omitempty"`
	IssuedAt                            Time     `json:"iat,omitempty"`
	JWTID                               string   `json:"jti,omitempty"`
	AuthorizedParty                     string   `json:"azp,omitempty"`
	Nonce                               string   `json:"nonce,omitempty"`
	AuthTime                            Time     `json:"auth_time,omitempty"`
	AccessTokenHash                     string   `json:"at_hash,omitempty"`
	CodeHash                            string   `json:"c_hash,omitempty"`
	AuthenticationContextClassReference string   `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string `json:"amr,omitempty"`
	ClientID                            string   `json:"client_id,omitempty"`
	UserInfo                            `json:"-"`

	signatureAlg jose.SignatureAlgorithm
}

func (t *idTokenClaims) SetAccessTokenHash(hash string) {
	t.AccessTokenHash = hash
}

func (t *idTokenClaims) SetUserinfo(info UserInfoSetter) {
	t.UserInfo = info
}

func (t *idTokenClaims) SetCodeHash(hash string) {
	t.CodeHash = hash
}

func EmptyIDTokenClaims() IDTokenClaims {
	return new(idTokenClaims)
}

func NewIDTokenClaims(issuer, subject string, audience []string, expiration, authTime time.Time, nonce string, acr string, amr []string, clientID string) IDTokenClaims {
	return &idTokenClaims{
		Issuer:                              issuer,
		Audience:                            audience,
		Expiration:                          Time(expiration),
		IssuedAt:                            Time(time.Now().UTC()),
		AuthTime:                            Time(authTime),
		Nonce:                               nonce,
		AuthenticationContextClassReference: acr,
		AuthenticationMethodsReferences:     amr,
		AuthorizedParty:                     clientID,
		UserInfo:                            &userinfo{Subject: subject},
	}
}

func (t *idTokenClaims) GetSignatureAlgorithm() jose.SignatureAlgorithm {
	return t.signatureAlg
}

func (t *idTokenClaims) GetNotBefore() time.Time {
	return time.Time(t.NotBefore)
}

func (t *idTokenClaims) GetJWTID() string {
	return t.JWTID
}

func (t *idTokenClaims) GetAccessTokenHash() string {
	return t.AccessTokenHash
}

func (t *idTokenClaims) GetCodeHash() string {
	return t.CodeHash
}

func (t *idTokenClaims) GetAuthenticationMethodsReferences() []string {
	return t.AuthenticationMethodsReferences
}

func (t *idTokenClaims) GetClientID() string {
	return t.ClientID
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty" schema:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty" schema:"refresh_token,omitempty"`
	ExpiresIn    uint64 `json:"expires_in,omitempty" schema:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty" schema:"id_token,omitempty"`
}

type JWTProfileAssertion struct {
	PrivateKeyID string   `json:"-"`
	PrivateKey   []byte   `json:"-"`
	Issuer       string   `json:"issuer"`
	Subject      string   `json:"sub"`
	Audience     Audience `json:"aud"`
	Expiration   Time     `json:"exp"`
	IssuedAt     Time     `json:"iat"`
}

func NewJWTProfileAssertionFromKeyJSON(filename string, audience []string) (*JWTProfileAssertion, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewJWTProfileAssertionFromFileData(data, audience)
}

func NewJWTProfileAssertionFromFileData(data []byte, audience []string) (*JWTProfileAssertion, error) {
	keyData := new(struct {
		KeyID  string `json:"keyId"`
		Key    string `json:"key"`
		UserID string `json:"userId"`
	})
	err := json.Unmarshal(data, keyData)
	if err != nil {
		return nil, err
	}
	return NewJWTProfileAssertion(keyData.UserID, keyData.KeyID, audience, []byte(keyData.Key)), nil
}

func NewJWTProfileAssertion(userID, keyID string, audience []string, key []byte) *JWTProfileAssertion {
	return &JWTProfileAssertion{
		PrivateKey:   key,
		PrivateKeyID: keyID,
		Issuer:       userID,
		Subject:      userID,
		IssuedAt:     Time(time.Now().UTC()),
		Expiration:   Time(time.Now().Add(1 * time.Hour).UTC()),
		Audience:     audience,
	}
}

func (t *idTokenClaims) MarshalJSON() ([]byte, error) {
	type Alias idTokenClaims
	a := &struct {
		*Alias
		Expiration int64 `json:"nbf,omitempty"`
		IssuedAt   int64 `json:"nbf,omitempty"`
		NotBefore  int64 `json:"nbf,omitempty"`
		AuthTime   int64 `json:"nbf,omitempty"`
	}{
		Alias: (*Alias)(t),
	}
	if !time.Time(t.Expiration).IsZero() {
		a.Expiration = time.Time(t.Expiration).Unix()
	}
	if !time.Time(t.IssuedAt).IsZero() {
		a.IssuedAt = time.Time(t.IssuedAt).Unix()
	}
	if !time.Time(t.NotBefore).IsZero() {
		a.NotBefore = time.Time(t.NotBefore).Unix()
	}
	if !time.Time(t.AuthTime).IsZero() {
		a.AuthTime = time.Time(t.AuthTime).Unix()
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	if t.UserInfo == nil {
		return b, nil
	}
	info, err := json.Marshal(t.UserInfo)
	if err != nil {
		return nil, err
	}
	return utils.ConcatenateJSON(b, info)
}

func (t *idTokenClaims) UnmarshalJSON(data []byte) error {
	type Alias idTokenClaims
	if err := json.Unmarshal(data, (*Alias)(t)); err != nil {
		return err
	}
	userinfo := new(userinfo)
	if err := json.Unmarshal(data, userinfo); err != nil {
		return err
	}
	t.UserInfo = userinfo

	return nil
}

func (t *idTokenClaims) GetIssuer() string {
	return t.Issuer
}

func (t *idTokenClaims) GetAudience() []string {
	return t.Audience
}

func (t *idTokenClaims) GetExpiration() time.Time {
	return time.Time(t.Expiration)
}

func (t *idTokenClaims) GetIssuedAt() time.Time {
	return time.Time(t.IssuedAt)
}

func (t *idTokenClaims) GetNonce() string {
	return t.Nonce
}

func (t *idTokenClaims) GetAuthenticationContextClassReference() string {
	return t.AuthenticationContextClassReference
}

func (t *idTokenClaims) GetAuthTime() time.Time {
	return time.Time(t.AuthTime)
}

func (t *idTokenClaims) GetAuthorizedParty() string {
	return t.AuthorizedParty
}

func (t *idTokenClaims) SetSignatureAlgorithm(alg jose.SignatureAlgorithm) {
	t.signatureAlg = alg
}

func ClaimHash(claim string, sigAlgorithm jose.SignatureAlgorithm) (string, error) {
	hash, err := utils.GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}

	return utils.HashString(hash, claim, true), nil
}

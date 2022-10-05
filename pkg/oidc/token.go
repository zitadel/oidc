package oidc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/pkg/crypto"
	"github.com/zitadel/oidc/pkg/http"
)

const (
	// BearerToken defines the token_type `Bearer`, which is returned in a successful token response
	BearerToken = "Bearer"

	PrefixBearer = BearerToken + " "
)

type Tokens struct {
	*oauth2.Token
	IDTokenClaims IDTokenClaims
	IDToken       string
}

type AccessTokenClaims interface {
	Claims
	GetSubject() string
	GetTokenID() string
	SetPrivateClaims(map[string]interface{})
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
	SetUserinfo(userinfo UserInfo)
	SetCodeHash(hash string)
	UserInfo
}

func EmptyAccessTokenClaims() AccessTokenClaims {
	return new(accessTokenClaims)
}

func NewAccessTokenClaims(issuer, subject string, audience []string, expiration time.Time, id, clientID string, skew time.Duration) AccessTokenClaims {
	now := time.Now().UTC().Add(-skew)
	if len(audience) == 0 {
		audience = append(audience, clientID)
	}
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

type accessTokenClaims struct {
	Issuer                              string   `json:"iss,omitempty"`
	Subject                             string   `json:"sub,omitempty"`
	Audience                            Audience `json:"aud,omitempty"`
	Expiration                          Time     `json:"exp,omitempty"`
	IssuedAt                            Time     `json:"iat,omitempty"`
	NotBefore                           Time     `json:"nbf,omitempty"`
	JWTID                               string   `json:"jti,omitempty"`
	AuthorizedParty                     string   `json:"azp,omitempty"`
	Nonce                               string   `json:"nonce,omitempty"`
	AuthTime                            Time     `json:"auth_time,omitempty"`
	CodeHash                            string   `json:"c_hash,omitempty"`
	AuthenticationContextClassReference string   `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string `json:"amr,omitempty"`
	SessionID                           string   `json:"sid,omitempty"`
	Scopes                              []string `json:"scope,omitempty"`
	ClientID                            string   `json:"client_id,omitempty"`
	AccessTokenUseNumber                int      `json:"at_use_nbr,omitempty"`

	claims       map[string]interface{}  `json:"-"`
	signatureAlg jose.SignatureAlgorithm `json:"-"`
}

// GetIssuer implements the Claims interface
func (a *accessTokenClaims) GetIssuer() string {
	return a.Issuer
}

// GetAudience implements the Claims interface
func (a *accessTokenClaims) GetAudience() []string {
	return a.Audience
}

// GetExpiration implements the Claims interface
func (a *accessTokenClaims) GetExpiration() time.Time {
	return time.Time(a.Expiration)
}

// GetIssuedAt implements the Claims interface
func (a *accessTokenClaims) GetIssuedAt() time.Time {
	return time.Time(a.IssuedAt)
}

// GetNonce implements the Claims interface
func (a *accessTokenClaims) GetNonce() string {
	return a.Nonce
}

// GetAuthenticationContextClassReference implements the Claims interface
func (a *accessTokenClaims) GetAuthenticationContextClassReference() string {
	return a.AuthenticationContextClassReference
}

// GetAuthTime implements the Claims interface
func (a *accessTokenClaims) GetAuthTime() time.Time {
	return time.Time(a.AuthTime)
}

// GetAuthorizedParty implements the Claims interface
func (a *accessTokenClaims) GetAuthorizedParty() string {
	return a.AuthorizedParty
}

// SetSignatureAlgorithm implements the Claims interface
func (a *accessTokenClaims) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {
	a.signatureAlg = algorithm
}

// GetSubject implements the AccessTokenClaims interface
func (a *accessTokenClaims) GetSubject() string {
	return a.Subject
}

// GetTokenID implements the AccessTokenClaims interface
func (a *accessTokenClaims) GetTokenID() string {
	return a.JWTID
}

// SetPrivateClaims implements the AccessTokenClaims interface
func (a *accessTokenClaims) SetPrivateClaims(claims map[string]interface{}) {
	a.claims = claims
}

func (a *accessTokenClaims) MarshalJSON() ([]byte, error) {
	type Alias accessTokenClaims
	s := &struct {
		*Alias
		Expiration int64 `json:"exp,omitempty"`
		IssuedAt   int64 `json:"iat,omitempty"`
		NotBefore  int64 `json:"nbf,omitempty"`
		AuthTime   int64 `json:"auth_time,omitempty"`
	}{
		Alias: (*Alias)(a),
	}
	if !time.Time(a.Expiration).IsZero() {
		s.Expiration = time.Time(a.Expiration).Unix()
	}
	if !time.Time(a.IssuedAt).IsZero() {
		s.IssuedAt = time.Time(a.IssuedAt).Unix()
	}
	if !time.Time(a.NotBefore).IsZero() {
		s.NotBefore = time.Time(a.NotBefore).Unix()
	}
	if !time.Time(a.AuthTime).IsZero() {
		s.AuthTime = time.Time(a.AuthTime).Unix()
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	if a.claims == nil {
		return b, nil
	}
	info, err := json.Marshal(a.claims)
	if err != nil {
		return nil, err
	}
	return http.ConcatenateJSON(b, info)
}

func (a *accessTokenClaims) UnmarshalJSON(data []byte) error {
	type Alias accessTokenClaims
	if err := json.Unmarshal(data, (*Alias)(a)); err != nil {
		return err
	}
	claims := make(map[string]interface{})
	if err := json.Unmarshal(data, &claims); err != nil {
		return err
	}
	a.claims = claims

	return nil
}

func EmptyIDTokenClaims() IDTokenClaims {
	return new(idTokenClaims)
}

func NewIDTokenClaims(issuer, subject string, audience []string, expiration, authTime time.Time, nonce string, acr string, amr []string, clientID string, skew time.Duration) IDTokenClaims {
	audience = AppendClientIDToAudience(clientID, audience)
	return &idTokenClaims{
		Issuer:                              issuer,
		Audience:                            audience,
		Expiration:                          Time(expiration),
		IssuedAt:                            Time(time.Now().UTC().Add(-skew)),
		AuthTime:                            Time(authTime.Add(-skew)),
		Nonce:                               nonce,
		AuthenticationContextClassReference: acr,
		AuthenticationMethodsReferences:     amr,
		AuthorizedParty:                     clientID,
		UserInfo:                            &userinfo{Subject: subject},
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

// GetIssuer implements the Claims interface
func (t *idTokenClaims) GetIssuer() string {
	return t.Issuer
}

// GetAudience implements the Claims interface
func (t *idTokenClaims) GetAudience() []string {
	return t.Audience
}

// GetExpiration implements the Claims interface
func (t *idTokenClaims) GetExpiration() time.Time {
	return time.Time(t.Expiration)
}

// GetIssuedAt implements the Claims interface
func (t *idTokenClaims) GetIssuedAt() time.Time {
	return time.Time(t.IssuedAt)
}

// GetNonce implements the Claims interface
func (t *idTokenClaims) GetNonce() string {
	return t.Nonce
}

// GetAuthenticationContextClassReference implements the Claims interface
func (t *idTokenClaims) GetAuthenticationContextClassReference() string {
	return t.AuthenticationContextClassReference
}

// GetAuthTime implements the Claims interface
func (t *idTokenClaims) GetAuthTime() time.Time {
	return time.Time(t.AuthTime)
}

// GetAuthorizedParty implements the Claims interface
func (t *idTokenClaims) GetAuthorizedParty() string {
	return t.AuthorizedParty
}

// SetSignatureAlgorithm implements the Claims interface
func (t *idTokenClaims) SetSignatureAlgorithm(alg jose.SignatureAlgorithm) {
	t.signatureAlg = alg
}

// GetNotBefore implements the IDTokenClaims interface
func (t *idTokenClaims) GetNotBefore() time.Time {
	return time.Time(t.NotBefore)
}

// GetJWTID implements the IDTokenClaims interface
func (t *idTokenClaims) GetJWTID() string {
	return t.JWTID
}

// GetAccessTokenHash implements the IDTokenClaims interface
func (t *idTokenClaims) GetAccessTokenHash() string {
	return t.AccessTokenHash
}

// GetCodeHash implements the IDTokenClaims interface
func (t *idTokenClaims) GetCodeHash() string {
	return t.CodeHash
}

// GetAuthenticationMethodsReferences implements the IDTokenClaims interface
func (t *idTokenClaims) GetAuthenticationMethodsReferences() []string {
	return t.AuthenticationMethodsReferences
}

// GetClientID implements the IDTokenClaims interface
func (t *idTokenClaims) GetClientID() string {
	return t.ClientID
}

// GetSignatureAlgorithm implements the IDTokenClaims interface
func (t *idTokenClaims) GetSignatureAlgorithm() jose.SignatureAlgorithm {
	return t.signatureAlg
}

// SetAccessTokenHash implements the IDTokenClaims interface
func (t *idTokenClaims) SetAccessTokenHash(hash string) {
	t.AccessTokenHash = hash
}

// SetUserinfo implements the IDTokenClaims interface
func (t *idTokenClaims) SetUserinfo(info UserInfo) {
	t.UserInfo = info
}

// SetCodeHash implements the IDTokenClaims interface
func (t *idTokenClaims) SetCodeHash(hash string) {
	t.CodeHash = hash
}

func (t *idTokenClaims) MarshalJSON() ([]byte, error) {
	type Alias idTokenClaims
	a := &struct {
		*Alias
		Expiration int64 `json:"exp,omitempty"`
		IssuedAt   int64 `json:"iat,omitempty"`
		NotBefore  int64 `json:"nbf,omitempty"`
		AuthTime   int64 `json:"auth_time,omitempty"`
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
	return http.ConcatenateJSON(b, info)
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

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty" schema:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty" schema:"refresh_token,omitempty"`
	ExpiresIn    uint64 `json:"expires_in,omitempty" schema:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty" schema:"id_token,omitempty"`
	State        string `json:"state,omitempty" schema:"state,omitempty"`
}

type JWTProfileAssertionClaims interface {
	GetKeyID() string
	GetPrivateKey() []byte
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
	GetExpiration() time.Time
	GetIssuedAt() time.Time
	SetCustomClaim(key string, value interface{})
	GetCustomClaim(key string) interface{}
}

type jwtProfileAssertion struct {
	PrivateKeyID string   `json:"-"`
	PrivateKey   []byte   `json:"-"`
	Issuer       string   `json:"iss"`
	Subject      string   `json:"sub"`
	Audience     Audience `json:"aud"`
	Expiration   Time     `json:"exp"`
	IssuedAt     Time     `json:"iat"`

	customClaims map[string]interface{}
}

func (j *jwtProfileAssertion) MarshalJSON() ([]byte, error) {
	type Alias jwtProfileAssertion
	a := (*Alias)(j)

	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	if len(j.customClaims) == 0 {
		return b, nil
	}

	err = json.Unmarshal(b, &j.customClaims)
	if err != nil {
		return nil, fmt.Errorf("jws: invalid map of custom claims %v", j.customClaims)
	}

	return json.Marshal(j.customClaims)
}

func (j *jwtProfileAssertion) UnmarshalJSON(data []byte) error {
	type Alias jwtProfileAssertion
	a := (*Alias)(j)

	err := json.Unmarshal(data, a)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &j.customClaims)
	if err != nil {
		return err
	}

	return nil
}

func (j *jwtProfileAssertion) GetKeyID() string {
	return j.PrivateKeyID
}

func (j *jwtProfileAssertion) GetPrivateKey() []byte {
	return j.PrivateKey
}

func (j *jwtProfileAssertion) SetCustomClaim(key string, value interface{}) {
	if j.customClaims == nil {
		j.customClaims = make(map[string]interface{})
	}
	j.customClaims[key] = value
}

func (j *jwtProfileAssertion) GetCustomClaim(key string) interface{} {
	if j.customClaims == nil {
		return nil
	}
	return j.customClaims[key]
}

func (j *jwtProfileAssertion) GetIssuer() string {
	return j.Issuer
}

func (j *jwtProfileAssertion) GetSubject() string {
	return j.Subject
}

func (j *jwtProfileAssertion) GetAudience() []string {
	return j.Audience
}

func (j *jwtProfileAssertion) GetExpiration() time.Time {
	return time.Time(j.Expiration)
}

func (j *jwtProfileAssertion) GetIssuedAt() time.Time {
	return time.Time(j.IssuedAt)
}

func NewJWTProfileAssertionFromKeyJSON(filename string, audience []string, opts ...AssertionOption) (JWTProfileAssertionClaims, error) {
	data, err := ioutil.ReadFile(filename)
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

func JWTProfileDelegatedSubject(sub string) func(*jwtProfileAssertion) {
	return func(j *jwtProfileAssertion) {
		j.Subject = sub
	}
}

func JWTProfileCustomClaim(key string, value interface{}) func(*jwtProfileAssertion) {
	return func(j *jwtProfileAssertion) {
		j.customClaims[key] = value
	}
}

func NewJWTProfileAssertionFromFileData(data []byte, audience []string, opts ...AssertionOption) (JWTProfileAssertionClaims, error) {
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

type AssertionOption func(*jwtProfileAssertion)

func NewJWTProfileAssertion(userID, keyID string, audience []string, key []byte, opts ...AssertionOption) JWTProfileAssertionClaims {
	j := &jwtProfileAssertion{
		PrivateKey:   key,
		PrivateKeyID: keyID,
		Issuer:       userID,
		Subject:      userID,
		IssuedAt:     Time(time.Now().UTC()),
		Expiration:   Time(time.Now().Add(1 * time.Hour).UTC()),
		Audience:     audience,
		customClaims: make(map[string]interface{}),
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

func GenerateJWTProfileToken(assertion JWTProfileAssertionClaims) (string, error) {
	privateKey, err := crypto.BytesToPrivateKey(assertion.GetPrivateKey())
	if err != nil {
		return "", err
	}
	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       &jose.JSONWebKey{Key: privateKey, KeyID: assertion.GetKeyID()},
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

package mock

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
)

type AuthStorage struct {
	key *rsa.PrivateKey
}

func NewAuthStorage() op.Storage {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}
	return &AuthStorage{
		key: key,
	}
}

type AuthRequest struct {
	ID            string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	RedirectURI   string
	Nonce         string
	ClientID      string
	CodeChallenge *oidc.CodeChallenge
	State         string
}

func (a *AuthRequest) GetACR() string {
	return ""
}

func (a *AuthRequest) GetAMR() []string {
	return []string{
		"password",
	}
}

func (a *AuthRequest) GetAudience() []string {
	return []string{
		a.ClientID,
	}
}

func (a *AuthRequest) GetAuthTime() time.Time {
	return time.Now().UTC()
}

func (a *AuthRequest) GetClientID() string {
	return a.ClientID
}

func (a *AuthRequest) GetCode() string {
	return "code"
}

func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return a.CodeChallenge
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetNonce() string {
	return a.Nonce
}

func (a *AuthRequest) GetRedirectURI() string {
	return a.RedirectURI
	// return "http://localhost:5556/auth/callback"
}

func (a *AuthRequest) GetResponseType() oidc.ResponseType {
	return a.ResponseType
}

func (a *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return a.ResponseMode
}

func (a *AuthRequest) GetScopes() []string {
	return []string{
		"openid",
		"profile",
		"email",
	}
}

func (a *AuthRequest) SetCurrentScopes(scopes []string) {}

func (a *AuthRequest) GetState() string {
	return a.State
}

func (a *AuthRequest) GetSubject() string {
	return "sub"
}

func (a *AuthRequest) Done() bool {
	return true
}

var (
	a = &AuthRequest{}
	t bool
	c string
)

func (s *AuthStorage) Health(ctx context.Context) error {
	return nil
}

func (s *AuthStorage) CreateAuthRequest(_ context.Context, authReq *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	a = &AuthRequest{ID: "id", ClientID: authReq.ClientID, ResponseType: authReq.ResponseType, Nonce: authReq.Nonce, RedirectURI: authReq.RedirectURI, State: authReq.State}
	if authReq.CodeChallenge != "" {
		a.CodeChallenge = &oidc.CodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    authReq.CodeChallengeMethod,
		}
	}
	t = false
	return a, nil
}
func (s *AuthStorage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	if code != c {
		return nil, errors.New("invalid code")
	}
	return a, nil
}
func (s *AuthStorage) SaveAuthCode(_ context.Context, id, code string) error {
	if a.ID != id {
		return errors.New("not found")
	}
	c = code
	return nil
}
func (s *AuthStorage) DeleteAuthRequest(context.Context, string) error {
	t = true
	return nil
}
func (s *AuthStorage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	if id != "id" || t {
		return nil, errors.New("not found")
	}
	return a, nil
}
func (s *AuthStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	return "id", time.Now().UTC().Add(5 * time.Minute), nil
}
func (s *AuthStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	return "id", "refreshToken", time.Now().UTC().Add(5 * time.Minute), nil
}
func (s *AuthStorage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	if refreshToken != c {
		return nil, errors.New("invalid token")
	}
	return a, nil
}

func (s *AuthStorage) TerminateSession(_ context.Context, userID, clientID string) error {
	return nil
}
func (s *AuthStorage) GetSigningKey(_ context.Context, keyCh chan<- jose.SigningKey) {
	keyCh <- jose.SigningKey{Algorithm: jose.RS256, Key: s.key}
}
func (s *AuthStorage) GetKey(_ context.Context) (*rsa.PrivateKey, error) {
	return s.key, nil
}
func (s *AuthStorage) GetKeySet(_ context.Context) (*jose.JSONWebKeySet, error) {
	pubkey := s.key.Public()
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: pubkey, Use: "sig", Algorithm: "RS256", KeyID: "1"},
		},
	}, nil
}
func (s *AuthStorage) GetKeyByIDAndUserID(_ context.Context, _, _ string) (*jose.JSONWebKey, error) {
	pubkey := s.key.Public()
	return &jose.JSONWebKey{Key: pubkey, Use: "sig", Algorithm: "RS256", KeyID: "1"}, nil
}

func (s *AuthStorage) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	if id == "none" {
		return nil, errors.New("not found")
	}
	var appType op.ApplicationType
	var authMethod oidc.AuthMethod
	var accessTokenType op.AccessTokenType
	var responseTypes []oidc.ResponseType
	if id == "web" {
		appType = op.ApplicationTypeWeb
		authMethod = oidc.AuthMethodBasic
		accessTokenType = op.AccessTokenTypeBearer
		responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
	} else if id == "native" {
		appType = op.ApplicationTypeNative
		authMethod = oidc.AuthMethodNone
		accessTokenType = op.AccessTokenTypeBearer
		responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
	} else {
		appType = op.ApplicationTypeUserAgent
		authMethod = oidc.AuthMethodNone
		accessTokenType = op.AccessTokenTypeJWT
		responseTypes = []oidc.ResponseType{oidc.ResponseTypeIDToken, oidc.ResponseTypeIDTokenOnly}
	}
	return &ConfClient{ID: id, applicationType: appType, authMethod: authMethod, accessTokenType: accessTokenType, responseTypes: responseTypes, devMode: false, grantTypes: []oidc.GrantType{oidc.GrantTypeCode}}, nil
}

func (s *AuthStorage) AuthorizeClientIDSecret(_ context.Context, id string, _ string) error {
	return nil
}

func (s *AuthStorage) SetUserinfoFromToken(ctx context.Context, userinfo oidc.UserInfoSetter, _, _, _ string) error {
	return s.SetUserinfoFromScopes(ctx, userinfo, "", "", []string{})
}
func (s *AuthStorage) SetUserinfoFromScopes(ctx context.Context, userinfo oidc.UserInfoSetter, _, _ string, _ []string) error {
	userinfo.SetSubject(a.GetSubject())
	userinfo.SetAddress(oidc.NewUserInfoAddress("Test 789\nPostfach 2", "", "", "", "", ""))
	userinfo.SetEmail("test", true)
	userinfo.SetPhone("0791234567", true)
	userinfo.SetName("Test")
	userinfo.AppendClaims("private_claim", "test")
	return nil
}
func (s *AuthStorage) GetPrivateClaimsFromScopes(_ context.Context, _, _ string, _ []string) (map[string]interface{}, error) {
	return map[string]interface{}{"private_claim": "test"}, nil
}

func (s *AuthStorage) SetIntrospectionFromToken(ctx context.Context, introspect oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	if err := s.SetUserinfoFromScopes(ctx, introspect, "", "", []string{}); err != nil {
		return err
	}
	introspect.SetClientID(a.ClientID)
	return nil
}

func (s *AuthStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scope []string) ([]string, error) {
	return scope, nil
}

type ConfClient struct {
	applicationType op.ApplicationType
	authMethod      oidc.AuthMethod
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	ID              string
	accessTokenType op.AccessTokenType
	devMode         bool
}

func (c *ConfClient) GetID() string {
	return c.ID
}
func (c *ConfClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://localhost:9999/callback",
		"http://localhost:5556/auth/callback",
		"custom://callback",
		"https://localhost:8443/test/a/instructions-example/callback",
		"https://op.certification.openid.net:62064/authz_cb",
		"https://op.certification.openid.net:62064/authz_post",
	}
}
func (c *ConfClient) PostLogoutRedirectURIs() []string {
	return []string{}
}

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}

func (c *ConfClient) ApplicationType() op.ApplicationType {
	return c.applicationType
}

func (c *ConfClient) AuthMethod() oidc.AuthMethod {
	return c.authMethod
}

func (c *ConfClient) IDTokenLifetime() time.Duration {
	return time.Duration(5 * time.Minute)
}
func (c *ConfClient) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}
func (c *ConfClient) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}
func (c *ConfClient) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *ConfClient) DevMode() bool {
	return c.devMode
}

func (c *ConfClient) AllowedScopes() []string {
	return nil
}

func (c *ConfClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *ConfClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *ConfClient) IsScopeAllowed(scope string) bool {
	return false
}

func (c *ConfClient) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

func (c *ConfClient) ClockSkew() time.Duration {
	return 0
}

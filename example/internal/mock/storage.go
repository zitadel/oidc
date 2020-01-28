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
	RedirectURI   string
	Nonce         string
	ClientID      string
	CodeChallenge *oidc.CodeChallenge
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

func (a *AuthRequest) GetScopes() []string {
	return []string{
		"openid",
		"profile",
		"email",
	}
}

func (a *AuthRequest) GetState() string {
	return ""
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
)

func (s *AuthStorage) CreateAuthRequest(_ context.Context, authReq *oidc.AuthRequest) (op.AuthRequest, error) {
	a = &AuthRequest{ID: "id", ClientID: authReq.ClientID, ResponseType: authReq.ResponseType, Nonce: authReq.Nonce, RedirectURI: authReq.RedirectURI}
	if authReq.CodeChallenge != "" {
		a.CodeChallenge = &oidc.CodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    authReq.CodeChallengeMethod,
		}
	}
	t = false
	return a, nil
}
func (s *AuthStorage) AuthRequestByCode(context.Context, string) (op.AuthRequest, error) {
	return a, nil
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
func (s *AuthStorage) GetSigningKey(_ context.Context) (*jose.SigningKey, error) {
	return &jose.SigningKey{Algorithm: jose.RS256, Key: s.key}, nil
}
func (s *AuthStorage) GetKey(_ context.Context) (*rsa.PrivateKey, error) {
	return s.key, nil
}
func (s *AuthStorage) SaveKeyPair(ctx context.Context) (*jose.SigningKey, error) {
	return s.GetSigningKey(ctx)
}
func (s *AuthStorage) GetKeySet(_ context.Context) (*jose.JSONWebKeySet, error) {
	pubkey := s.key.Public()
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			jose.JSONWebKey{Key: pubkey, Use: "sig", Algorithm: "RS256", KeyID: "1"},
		},
	}, nil
}

func (s *AuthStorage) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	if id == "none" {
		return nil, errors.New("not found")
	}
	var appType op.ApplicationType
	var authMethod op.AuthMethod
	var accessTokenType op.AccessTokenType
	if id == "web" {
		appType = op.ApplicationTypeWeb
		authMethod = op.AuthMethodBasic
		accessTokenType = op.AccessTokenTypeBearer
	} else if id == "native" {
		appType = op.ApplicationTypeNative
		authMethod = op.AuthMethodNone
		accessTokenType = op.AccessTokenTypeBearer
	} else {
		appType = op.ApplicationTypeUserAgent
		authMethod = op.AuthMethodNone
		accessTokenType = op.AccessTokenTypeJWT
	}
	return &ConfClient{ID: id, applicationType: appType, authMethod: authMethod, accessTokenType: accessTokenType}, nil
}

func (s *AuthStorage) AuthorizeClientIDSecret(_ context.Context, id string, _ string) error {
	return nil
}

func (s *AuthStorage) GetUserinfoFromScopes(context.Context, []string) (*oidc.Userinfo, error) {
	return &oidc.Userinfo{
		Subject: a.GetSubject(),
		Address: &oidc.UserinfoAddress{
			StreetAddress: "Hjkhkj 789\ndsf",
		},
		UserinfoEmail: oidc.UserinfoEmail{
			Email:         "test",
			EmailVerified: true,
		},
		UserinfoPhone: oidc.UserinfoPhone{
			PhoneNumber:         "sadsa",
			PhoneNumberVerified: true,
		},
		UserinfoProfile: oidc.UserinfoProfile{
			UpdatedAt: time.Now(),
		},
		// Claims: map[string]interface{}{
		// 	"test": "test",
		// 	"hkjh": "",
		// },
	}, nil
}

type ConfClient struct {
	applicationType op.ApplicationType
	authMethod      op.AuthMethod
	ID              string
	accessTokenType op.AccessTokenType
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

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}

func (c *ConfClient) ApplicationType() op.ApplicationType {
	return c.applicationType
}

func (c *ConfClient) GetAuthMethod() op.AuthMethod {
	return c.authMethod
}

func (c *ConfClient) AccessTokenLifetime() time.Duration {
	return time.Duration(5 * time.Minute)
}
func (c *ConfClient) IDTokenLifetime() time.Duration {
	return time.Duration(5 * time.Minute)
}
func (c *ConfClient) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}

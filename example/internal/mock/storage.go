package mock

import (
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

type OPStorage struct{}

func NewAuthStorage() op.AuthStorage {
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
	ID           string
	ResponseType oidc.ResponseType
	RedirectURI  string
	Nonce        string
	ClientID     string
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

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetNonce() string {
	return a.Nonce
}

func (a *AuthRequest) GetRedirectURI() string {
	return "https://op.certification.openid.net:62054/authz_cb"
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

var (
	a = &AuthRequest{}
)

func (s *AuthStorage) CreateAuthRequest(authReq *oidc.AuthRequest) (op.AuthRequest, error) {
	a = &AuthRequest{ID: "id", ClientID: authReq.ClientID, ResponseType: authReq.ResponseType, Nonce: authReq.Nonce}
	return a, nil
}
func (s *OPStorage) GetClientByClientID(id string) (op.Client, error) {
	if id == "none" {
		return nil, errors.New("not found")
	}
	var appType op.ApplicationType
	if id == "web" {
		appType = op.ApplicationTypeWeb
	} else if id == "native" {
		appType = op.ApplicationTypeNative
	} else {
		appType = op.ApplicationTypeUserAgent
	}
	return &ConfClient{applicationType: appType}, nil
}
func (s *AuthStorage) AuthRequestByCode(op.Client, string, string) (op.AuthRequest, error) {
	return a, nil
}
func (s *OPStorage) AuthorizeClientIDSecret(string, string) (op.Client, error) {
	return &ConfClient{}, nil
}
func (s *OPStorage) AuthorizeClientIDCodeVerifier(string, string) (op.Client, error) {
	return &ConfClient{}, nil
}
func (s *AuthStorage) DeleteAuthRequestAndCode(string, string) error {
	return nil
}
func (s *AuthStorage) AuthRequestByID(id string) (op.AuthRequest, error) {
	if id == "none" {
		return nil, errors.New("not found")
	}
	var responseType oidc.ResponseType
	if id == "code" {
		responseType = oidc.ResponseTypeCode
	} else if id == "id" {
		responseType = oidc.ResponseTypeIDTokenOnly
	} else {
		responseType = oidc.ResponseTypeIDToken
	}
	return &AuthRequest{
		ResponseType: responseType,
		RedirectURI:  "/callback",
	}, nil
}

func (s *AuthStorage) GetSigningKey() (*jose.SigningKey, error) {
	return &jose.SigningKey{Algorithm: jose.RS256, Key: s.key}, nil
}
func (s *AuthStorage) GetKey() (*rsa.PrivateKey, error) {
	return s.key, nil
}
func (s *AuthStorage) GetKeySet() (jose.JSONWebKeySet, error) {
	pubkey := s.key.Public()
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			jose.JSONWebKey{Key: pubkey, Use: "sig", Algorithm: "RS256", KeyID: "1"},
		},
	}, nil
}

type ConfClient struct {
	applicationType op.ApplicationType
}

func (c *ConfClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://localhost:9999/callback",
		"http://localhost:5556/auth/callback",
		"custom://callback",
		"https://localhost:8443/test/a/instructions-example/callback",
		"https://op.certification.openid.net:62054/authz_cb",
		"https://op.certification.openid.net:62054/authz_post",
	}
}

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}

func (c *ConfClient) ApplicationType() op.ApplicationType {
	return c.applicationType
}

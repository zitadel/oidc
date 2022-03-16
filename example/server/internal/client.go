package internal

import (
	"time"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
)

var clients = map[string]*Client{}

func RegisterClients(registerClients ...*Client) {
	for _, client := range registerClients {
		clients[client.id] = client
	}
}

//NativeClient will create a client of type native, which will always use PKCE and allow the use of refresh tokens
//user-defined redirectURIs may include:
// - http://localhost without port specification (e.g. http://localhost/auth/callback)
// - custom protocol (e.g. custom://auth/callback)
//(the examples will be used as default, if none is provided)
func NativeClient(id string, redirectURIs ...string) *Client {
	if len(redirectURIs) == 0 {
		redirectURIs = []string{
			"http://localhost/auth/callback",
			"custom://auth/callback",
		}
	}
	return &Client{
		id:                             id,
		secret:                         "", //no secret needed (due to PKCE)
		redirectURIs:                   redirectURIs,
		applicationType:                op.ApplicationTypeNative,
		authMethod:                     oidc.AuthMethodNone,
		defaultLoginURL:                defaultLoginURL,
		responseTypes:                  []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:                     []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		accessTokenType:                0,
		devMode:                        false,
		idTokenUserinfoClaimsAssertion: false,
		clockSkew:                      0,
	}
}

//WebClient will create a client of type web, which will always use PKCE and allow the use of refresh tokens
//user-defined redirectURIs may include:
// - http://localhost without port specification (e.g. http://localhost/auth/callback)
//(the example will be used as default, if none is provided)
func WebClient(id, secret string, redirectURIs ...string) *Client {
	return &Client{
		id:     id,
		secret: secret,
		redirectURIs: []string{
			"http://localhost:9999/auth/callback",
		},
		applicationType:                op.ApplicationTypeWeb,
		authMethod:                     oidc.AuthMethodBasic,
		defaultLoginURL:                defaultLoginURL,
		responseTypes:                  []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:                     []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		accessTokenType:                0,
		devMode:                        false,
		idTokenUserinfoClaimsAssertion: false,
		clockSkew:                      0,
	}
}

type Client struct {
	id                             string
	secret                         string
	redirectURIs                   []string
	applicationType                op.ApplicationType
	authMethod                     oidc.AuthMethod
	defaultLoginURL                func(string) string
	responseTypes                  []oidc.ResponseType
	grantTypes                     []oidc.GrantType
	accessTokenType                op.AccessTokenType
	devMode                        bool
	idTokenUserinfoClaimsAssertion bool
	clockSkew                      time.Duration
}

func (c *Client) GetID() string {
	return c.id
}

func (c *Client) RedirectURIs() []string {
	return c.redirectURIs
}

func (c *Client) PostLogoutRedirectURIs() []string {
	return []string{}
}

func (c *Client) ApplicationType() op.ApplicationType {
	return c.applicationType
}

func (c *Client) AuthMethod() oidc.AuthMethod {
	return c.authMethod
}

func (c *Client) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}

func (c *Client) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *Client) LoginURL(id string) string {
	//we use the default login UI and pass the (auth request) id,
	//but you could implement some logic here to redirect the users to different login UIs depending on the client
	return c.defaultLoginURL(id)
}

func (c *Client) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}

func (c *Client) IDTokenLifetime() time.Duration {
	return 1 * time.Hour
}

func (c *Client) DevMode() bool {
	return c.devMode
}

func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (c *Client) IsScopeAllowed(scope string) bool {
	return false
}

func (c *Client) IDTokenUserinfoClaimsAssertion() bool {
	return c.idTokenUserinfoClaimsAssertion
}

func (c *Client) ClockSkew() time.Duration {
	return c.clockSkew
}

package op

import (
	"context"
	"net/http"
	"net/url"

	"github.com/muhlemmer/gu"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Server describes the interface that needs to be implemented to serve
// OpenID Connect and Oauth2 standard requests.
//
// Methods are called after the HTTP route is resolved and
// the request body is parsed into the Request's Data field.
// When a method is called, it can be assumed that required fields,
// as described in their relevant standard, are validated already.
// The Response Data field may be of any type to allow flexibility
// to extend responses with custom fields. There are however requirements
// in the standards regarding the response models. Where applicable
// the method documentation gives a recommended type which can be used
// directly or extended upon.
//
// The addition of new methods is not considered a breaking change
// as defined by semver rules.
// Implementations MUST embed [UnimplementedServer] to maintain
// forward compatibility.
//
// EXPERIMENTAL: may change until v4
type Server interface {
	// Health returns a status of "ok" once the Server is listening.
	// The recommended Response Data type is [Status].
	Health(context.Context, *Request[struct{}]) (*Response, error)

	// Ready returns a status of "ok" once all dependencies,
	// such as database storage, are ready.
	// An error can be returned to explain what is not ready.
	// The recommended Response Data type is [Status].
	Ready(context.Context, *Request[struct{}]) (*Response, error)

	// Discovery returns the OpenID Provider Configuration Information for this server.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	// The recommended Response Data type is [oidc.DiscoveryConfiguration].
	Discovery(context.Context, *Request[struct{}]) (*Response, error)

	// Keys serves the JWK set which the client can use verify signatures from the op.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata `jwks_uri` key.
	// The recommended Response Data type is [jose.JSONWebKeySet].
	Keys(context.Context, *Request[struct{}]) (*Response, error)

	// VerifyAuthRequest verifies the Auth Request and
	// adds the Client to the request.
	//
	// When the `request` field is populated with a
	// "Request Object" JWT, it needs to be Validated
	// and its claims overwrite any fields in the AuthRequest.
	// If the implementation does not support "Request Object",
	// it MUST return an [oidc.ErrRequestNotSupported].
	// https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
	VerifyAuthRequest(context.Context, *Request[oidc.AuthRequest]) (*ClientRequest[oidc.AuthRequest], error)

	// Authorize initiates the authorization flow and redirects to a login page.
	// See the various https://openid.net/specs/openid-connect-core-1_0.html
	// authorize endpoint sections (one for each type of flow).
	Authorize(context.Context, *ClientRequest[oidc.AuthRequest]) (*Redirect, error)

	// DeviceAuthorization initiates the device authorization flow.
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
	// The recommended Response Data type is [oidc.DeviceAuthorizationResponse].
	DeviceAuthorization(context.Context, *ClientRequest[oidc.DeviceAuthorizationRequest]) (*Response, error)

	// VerifyClient is called on most oauth/token handlers to authenticate,
	// using either a secret (POST, Basic) or assertion (JWT).
	// If no secrets are provided, the client must be public.
	// This method is called before each method that takes a
	// [ClientRequest] argument.
	VerifyClient(context.Context, *Request[ClientCredentials]) (Client, error)

	// CodeExchange returns Tokens after an authorization code
	// is obtained in a successful Authorize flow.
	// It is called by the Token endpoint handler when
	// grant_type has the value authorization_code
	// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
	// The recommended Response Data type is [oidc.AccessTokenResponse].
	CodeExchange(context.Context, *ClientRequest[oidc.AccessTokenRequest]) (*Response, error)

	// RefreshToken returns new Tokens after verifying a Refresh token.
	// It is called by the Token endpoint handler when
	// grant_type has the value refresh_token
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
	// The recommended Response Data type is [oidc.AccessTokenResponse].
	RefreshToken(context.Context, *ClientRequest[oidc.RefreshTokenRequest]) (*Response, error)

	// JWTProfile handles the OAuth 2.0 JWT Profile Authorization Grant
	// It is called by the Token endpoint handler when
	// grant_type has the value urn:ietf:params:oauth:grant-type:jwt-bearer
	// https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
	// The recommended Response Data type is [oidc.AccessTokenResponse].
	JWTProfile(context.Context, *Request[oidc.JWTProfileGrantRequest]) (*Response, error)

	// TokenExchange handles the OAuth 2.0 token exchange grant
	// It is called by the Token endpoint handler when
	// grant_type has the value urn:ietf:params:oauth:grant-type:token-exchange
	// https://datatracker.ietf.org/doc/html/rfc8693
	// The recommended Response Data type is [oidc.AccessTokenResponse].
	TokenExchange(context.Context, *ClientRequest[oidc.TokenExchangeRequest]) (*Response, error)

	// ClientCredentialsExchange handles the OAuth 2.0 client credentials grant
	// It is called by the Token endpoint handler when
	// grant_type has the value client_credentials
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
	// The recommended Response Data type is [oidc.AccessTokenResponse].
	ClientCredentialsExchange(context.Context, *ClientRequest[oidc.ClientCredentialsRequest]) (*Response, error)

	// DeviceToken handles the OAuth 2.0 Device Authorization Grant
	// It is called by the Token endpoint handler when
	// grant_type has the value urn:ietf:params:oauth:grant-type:device_code.
	// It is typically called in a polling fashion and appropriate errors
	// should be returned to signal authorization_pending or access_denied etc.
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.4,
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.5.
	// The recommended Response Data type is [oidc.AccessTokenResponse].
	DeviceToken(context.Context, *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response, error)

	// Introspect handles the OAuth 2.0 Token Introspection endpoint.
	// https://datatracker.ietf.org/doc/html/rfc7662
	// The recommended Response Data type is [oidc.IntrospectionResponse].
	Introspect(context.Context, *Request[IntrospectionRequest]) (*Response, error)

	// UserInfo handles the UserInfo endpoint and returns Claims about the authenticated End-User.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	// The recommended Response Data type is [oidc.UserInfo].
	UserInfo(context.Context, *Request[oidc.UserInfoRequest]) (*Response, error)

	// Revocation handles token revocation using an access or refresh token.
	// https://datatracker.ietf.org/doc/html/rfc7009
	// There are no response requirements. Data may remain empty.
	Revocation(context.Context, *ClientRequest[oidc.RevocationRequest]) (*Response, error)

	// EndSession handles the OpenID Connect RP-Initiated Logout.
	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
	// There are no response requirements. Data may remain empty.
	EndSession(context.Context, *Request[oidc.EndSessionRequest]) (*Redirect, error)

	// mustImpl forces implementations to embed the UnimplementedServer for forward
	// compatibility with the interface.
	mustImpl()
}

// Request contains the [http.Request] informational fields
// and parsed Data from the request body (POST) or URL parameters (GET).
// Data can be assumed to be validated according to the applicable
// standard for the specific endpoints.
//
// EXPERIMENTAL: may change until v4
type Request[T any] struct {
	Method   string
	URL      *url.URL
	Header   http.Header
	Form     url.Values
	PostForm url.Values
	Data     *T
}

func (r *Request[_]) path() string {
	return r.URL.Path
}

func newRequest[T any](r *http.Request, data *T) *Request[T] {
	return &Request[T]{
		Method:   r.Method,
		URL:      r.URL,
		Header:   r.Header,
		Form:     r.Form,
		PostForm: r.PostForm,
		Data:     data,
	}
}

// ClientRequest is a Request with a verified client attached to it.
// Methods that receive this argument may assume the client was authenticated,
// or verified to be a public client.
//
// EXPERIMENTAL: may change until v4
type ClientRequest[T any] struct {
	*Request[T]
	Client Client
}

func newClientRequest[T any](r *http.Request, data *T, client Client) *ClientRequest[T] {
	return &ClientRequest[T]{
		Request: newRequest[T](r, data),
		Client:  client,
	}
}

// Response object for most [Server] methods.
//
// EXPERIMENTAL: may change until v4
type Response struct {
	// Header map will be merged with the
	// header on the [http.ResponseWriter].
	Header http.Header

	// Data will be JSON marshaled to
	// the response body.
	// We allow any type, so that implementations
	// can extend the standard types as they wish.
	// However, each method will recommend which
	// (base) type to use as model, in order to
	// be compliant with the standards.
	Data any
}

// NewResponse creates a new response for data,
// without custom headers.
func NewResponse(data any) *Response {
	return &Response{
		Header: make(http.Header),
		Data:   data,
	}
}

func (resp *Response) writeOut(w http.ResponseWriter) {
	gu.MapMerge(resp.Header, w.Header())
	httphelper.MarshalJSON(w, resp.Data)
}

// Redirect is a special response type which will
// initiate a [http.StatusFound] redirect.
// The Params field will be encoded and set to the
// URL's RawQuery field before building the URL.
//
// EXPERIMENTAL: may change until v4
type Redirect struct {
	// Header map will be merged with the
	// header on the [http.ResponseWriter].
	Header http.Header

	URL string
}

func NewRedirect(url string) *Redirect {
	return &Redirect{
		Header: make(http.Header),
		URL:    url,
	}
}

func (red *Redirect) writeOut(w http.ResponseWriter, r *http.Request) {
	gu.MapMerge(red.Header, w.Header())
	http.Redirect(w, r, red.URL, http.StatusFound)
}

type UnimplementedServer struct{}

// UnimplementedStatusCode is the status code returned for methods
// that are not yet implemented.
// Note that this means methods in the sense of the Go interface,
// and not http methods covered by "501 Not Implemented".
var UnimplementedStatusCode = http.StatusNotFound

func unimplementedError(r interface{ path() string }) StatusError {
	err := oidc.ErrServerError().WithDescription("%s not implemented on this server", r.path())
	return NewStatusError(err, UnimplementedStatusCode)
}

func unimplementedGrantError(gt oidc.GrantType) StatusError {
	err := oidc.ErrUnsupportedGrantType().WithDescription("%s not supported", gt)
	return NewStatusError(err, http.StatusBadRequest) // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
}

func (UnimplementedServer) mustImpl() {}

func (UnimplementedServer) Health(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Ready(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Discovery(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Keys(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) VerifyAuthRequest(ctx context.Context, r *Request[oidc.AuthRequest]) (*ClientRequest[oidc.AuthRequest], error) {
	if r.Data.RequestParam != "" {
		return nil, oidc.ErrRequestNotSupported()
	}
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Authorize(ctx context.Context, r *ClientRequest[oidc.AuthRequest]) (*Redirect, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) DeviceAuthorization(ctx context.Context, r *ClientRequest[oidc.DeviceAuthorizationRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) VerifyClient(ctx context.Context, r *Request[ClientCredentials]) (Client, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) CodeExchange(ctx context.Context, r *ClientRequest[oidc.AccessTokenRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeCode)
}

func (UnimplementedServer) RefreshToken(ctx context.Context, r *ClientRequest[oidc.RefreshTokenRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeRefreshToken)
}

func (UnimplementedServer) JWTProfile(ctx context.Context, r *Request[oidc.JWTProfileGrantRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeBearer)
}

func (UnimplementedServer) TokenExchange(ctx context.Context, r *ClientRequest[oidc.TokenExchangeRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeTokenExchange)
}

func (UnimplementedServer) ClientCredentialsExchange(ctx context.Context, r *ClientRequest[oidc.ClientCredentialsRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeClientCredentials)
}

func (UnimplementedServer) DeviceToken(ctx context.Context, r *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeDeviceCode)
}

func (UnimplementedServer) Introspect(ctx context.Context, r *Request[IntrospectionRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) UserInfo(ctx context.Context, r *Request[oidc.UserInfoRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Revocation(ctx context.Context, r *ClientRequest[oidc.RevocationRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) EndSession(ctx context.Context, r *Request[oidc.EndSessionRequest]) (*Redirect, error) {
	return nil, unimplementedError(r)
}

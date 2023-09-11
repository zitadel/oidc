package op

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/muhlemmer/gu"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type StatusError struct {
	parent     error
	statusCode int
}

func NewStatusError(parent error, statusCode int) StatusError {
	return StatusError{
		parent:     parent,
		statusCode: statusCode,
	}
}

func (e StatusError) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.statusCode), e.parent.Error())
}

func (e StatusError) Unwrap() error {
	return e.parent
}

func (e StatusError) Is(err error) bool {
	var target StatusError
	if !errors.As(err, &target) {
		return false
	}
	return errors.Is(e.parent, target.parent) &&
		e.statusCode == target.statusCode
}

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
type Server interface {
	// Health should return a status of "ok" once the Server is listining.
	// The recommended Response Data type is [Status].
	Health(context.Context, *Request[struct{}]) (*Response, error)

	// Ready should return a status of "ok" once all dependecies,
	// such as database storage are ready.
	// An error can be returned to explain what is not ready.
	// The recommended Response Data type is [Status].
	Ready(context.Context, *Request[struct{}]) (*Response, error)

	// Discovery return the OpenID Provider Configuration Information for this server.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	// The recommended Response Data type is [oidc.DiscoveryConfiguration].
	Discovery(context.Context, *Request[struct{}]) (*Response, error)

	// Authorize initiates the authorization flow and redirects to a login page.
	// See the various https://openid.net/specs/openid-connect-core-1_0.html
	// authorize endpoint sections (one for each type of flow).
	Authorize(context.Context, *Request[oidc.AuthRequest]) (*Redirect, error)

	// AuthorizeCallback? Do we still need it?

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
	// is obtained in a succesfull Authorize flow.
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
	// It is typically called in a polling fashion and appropiate errors
	// should be returned to signal authorization_pending or access_denied etc.
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.4,
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.5.
	// The recommended Response Data type is [oidc.AccessTokenResponse].
	DeviceToken(context.Context, *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response, error)

	// Introspect handles the OAuth 2.0 Token Introspection endpoint.
	// https://datatracker.ietf.org/doc/html/rfc7662
	// The recommended Response Data type is [oidc.IntrospectionResponse].
	Introspect(context.Context, *ClientRequest[oidc.IntrospectionRequest]) (*Response, error)

	// UserInfo handles the UserInfo endpoint and returns Claims about the authenticated End-User.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	// The recommended Response Data type is [oidc.UserInfo].
	UserInfo(context.Context, *Request[oidc.UserInfoRequest]) (*Response, error)

	// Revocation handles token revocation using an access or refresh token.
	// https://datatracker.ietf.org/doc/html/rfc7009
	// There are no response requirements. Data may remain empty.
	Revocation(context.Context, *Request[oidc.RevocationRequest]) (*Response, error)

	// EndSession handles the OpenID Connect RP-Initiated Logout.
	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
	// There are no response requirements. Data may remain empty.
	EndSession(context.Context, *Request[oidc.EndSessionRequest]) (*Response, error)

	// Keys serves the JWK set which the client can use verify signatures from the op.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata `jwks_uri` key.
	// The recommended Response Data type is [jose.JSOMWebKeySet].
	Keys(context.Context, *Request[struct{}]) (*Response, error)

	// mustImpl forces implementations to embed the UnimplementedServer for forward
	// compatibilty with the interface.
	mustImpl()
}

// Request contains the [http.Request] informational fields
// and parsed Data from the request body (POST) or URL parameters (GET).
// Data can be assumed to be validated according to the applicable
// standard for the specific endpoints.
type Request[T any] struct {
	Method   string
	URL      *url.URL
	Header   http.Header
	Form     url.Values
	PostForm url.Values
	Data     *T
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
// Methods the recieve this argument may assume the client was authenticated,
// or verified to be a public client.
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
	// be complaint with the standards.
	Data any
}

func NewResponse(data any) *Response {
	return &Response{
		Data: data,
	}
}

func (resp *Response) writeOut(w http.ResponseWriter) {
	gu.MapMerge(resp.Header, w.Header())
	json.NewEncoder(w).Encode(resp.Data)
}

// Redirect is a special response type which will
// initiate a [http.StatusFound] redirect.
// The Params fielde will be encoded and set to the
// URL's RawQuery field before building the URL.
type Redirect struct {
	// Header map will be merged with the
	// header on the [http.ResponseWriter].
	Header http.Header

	URL string
}

func NewRedirect(url string) *Redirect {
	return &Redirect{URL: url}
}

type UnimplementedServer struct{}

// UnimplementedStatusCode is the statuscode returned for methods
// that are not yet implemented.
// Note that this means methods in the sense of the Go interface,
// and not http methods covered by "501 Not Implemented".
var UnimplementedStatusCode = http.StatusNotFound

func unimplementedError[T any](r *Request[T]) StatusError {
	err := oidc.ErrServerError().WithDescription("%s not implemented on this server", r.URL.Path)
	return StatusError{
		parent:     err,
		statusCode: UnimplementedStatusCode,
	}
}

func unimplementedGrantError(gt oidc.GrantType) StatusError {
	err := oidc.ErrUnsupportedGrantType().WithDescription("%s grant not supported", gt)
	return NewStatusError(err, http.StatusBadRequest) // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
}

func (UnimplementedServer) mustImpl() {}

func (UnimplementedServer) Health(_ context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Ready(_ context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Discovery(_ context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Authorize(_ context.Context, r *Request[oidc.AuthRequest]) (*Redirect, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) DeviceAuthorization(_ context.Context, r *ClientRequest[oidc.DeviceAuthorizationRequest]) (*Response, error) {
	return nil, unimplementedError(r.Request)
}

func (UnimplementedServer) VerifyClient(_ context.Context, r *Request[ClientCredentials]) (Client, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) CodeExchange(_ context.Context, r *ClientRequest[oidc.AccessTokenRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeCode)
}

func (UnimplementedServer) RefreshToken(_ context.Context, r *ClientRequest[oidc.RefreshTokenRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeRefreshToken)
}

func (UnimplementedServer) JWTProfile(_ context.Context, r *Request[oidc.JWTProfileGrantRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeBearer)
}

func (UnimplementedServer) TokenExchange(_ context.Context, r *ClientRequest[oidc.TokenExchangeRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeTokenExchange)
}

func (UnimplementedServer) ClientCredentialsExchange(_ context.Context, r *ClientRequest[oidc.ClientCredentialsRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeClientCredentials)
}

func (UnimplementedServer) DeviceToken(_ context.Context, r *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response, error) {
	return nil, unimplementedGrantError(oidc.GrantTypeDeviceCode)
}

func (UnimplementedServer) Introspect(_ context.Context, r *ClientRequest[oidc.IntrospectionRequest]) (*Response, error) {
	return nil, unimplementedError(r.Request)
}

func (UnimplementedServer) UserInfo(_ context.Context, r *Request[oidc.UserInfoRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Revocation(_ context.Context, r *Request[oidc.RevocationRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) EndSession(_ context.Context, r *Request[oidc.EndSessionRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Keys(_ context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

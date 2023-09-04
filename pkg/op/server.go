package op

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	jose "github.com/go-jose/go-jose/v3"
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

type Request[T any] struct {
	Method string
	URL    *url.URL
	Header http.Header
	Form   url.Values
	Data   *T
}

func newRequest[T any](r *http.Request, data *T) *Request[T] {
	return &Request[T]{
		Method: r.Method,
		URL:    r.URL,
		Header: r.Header,
		Form:   r.Form,
		Data:   data,
	}
}

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

type Response[T any] struct {
	Header http.Header
	Data   *T
}

func NewResponse[T any](data *T) *Response[T] {
	return &Response[T]{
		Data: data,
	}
}

func (resp *Response[T]) writeOut(w http.ResponseWriter) {
	gu.MapMerge(resp.Header, w.Header())
	json.NewEncoder(w).Encode(resp.Data)
}

type Server interface {
	// Health should return a status of "ok" once the Server is listining.
	Health(context.Context, *Request[struct{}]) (*Response[Status], error)

	// Ready should return a status of "ok" once all dependecies,
	// such as database storage are ready.
	// An error can be returned to explain what is not ready.
	Ready(context.Context, *Request[struct{}]) (*Response[Status], error)

	// Discovery return the OpenID Provider Configuration Information for this server.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	Discovery(context.Context, *Request[struct{}]) (*Response[oidc.DiscoveryConfiguration], error)

	// Authorize initiates the authorization flow and redirects to a login page.
	// See the various https://openid.net/specs/openid-connect-core-1_0.html
	// authorize endpoint sections (one for each type of flow).
	Authorize(context.Context, *Request[oidc.AuthRequest]) (*Response[url.URL], error)

	// AuthorizeCallback? Do we still need it?

	// DeviceAuthorization initiates the device authorization flow.
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
	DeviceAuthorization(context.Context, *Request[oidc.DeviceAuthorizationRequest]) (*Response[oidc.DeviceAuthorizationResponse], error)

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
	CodeExchange(context.Context, *ClientRequest[oidc.AccessTokenRequest]) (*Response[oidc.AccessTokenResponse], error)

	// RefreshToken returns new Tokens after verifying a Refresh token.
	// It is called by the Token endpoint handler when
	// grant_type has the value refresh_token
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
	RefreshToken(context.Context, *ClientRequest[oidc.RefreshTokenRequest]) (*Response[oidc.AccessTokenResponse], error)

	// JWTProfile handles the OAuth 2.0 JWT Profile Authorization Grant
	// It is called by the Token endpoint handler when
	// grant_type has the value urn:ietf:params:oauth:grant-type:jwt-bearer
	// https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
	JWTProfile(context.Context, *Request[oidc.JWTProfileGrantRequest]) (*Response[oidc.AccessTokenResponse], error)

	// TokenExchange handles the OAuth 2.0 token exchange grant
	// It is called by the Token endpoint handler when
	// grant_type has the value urn:ietf:params:oauth:grant-type:token-exchange
	// https://datatracker.ietf.org/doc/html/rfc8693
	TokenExchange(context.Context, *ClientRequest[oidc.TokenExchangeRequest]) (*Response[oidc.AccessTokenResponse], error)

	// ClientCredentialsExchange handles the OAuth 2.0 client credentials grant
	// It is called by the Token endpoint handler when
	// grant_type has the value client_credentials
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
	ClientCredentialsExchange(context.Context, *ClientRequest[oidc.ClientCredentialsRequest]) (*Response[oidc.AccessTokenResponse], error)

	// DeviceToken handles the OAuth 2.0 Device Authorization Grant
	// It is called by the Token endpoint handler when
	// grant_type has the value urn:ietf:params:oauth:grant-type:device_code.
	// It is typically called in a polling fashion and appropiate errors
	// should be returned to signal authorization_pending or access_denied etc.
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.4,
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.5.
	DeviceToken(context.Context, *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response[oidc.AccessTokenResponse], error)

	// Introspect handles the OAuth 2.0 Token Introspection endpoint.
	// https://datatracker.ietf.org/doc/html/rfc7662
	Introspect(context.Context, *Request[oidc.IntrospectionRequest]) (*Response[oidc.IntrospectionResponse], error)

	// UserInfo handles the UserInfo endpoint and returns Claims about the authenticated End-User.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	UserInfo(context.Context, *Request[oidc.UserInfoRequest]) (*Response[oidc.UserInfo], error)

	// Revocation handles token revocation using an access or refresh token.
	// https://datatracker.ietf.org/doc/html/rfc7009
	Revocation(context.Context, *Request[oidc.RevocationRequest]) (*Response[struct{}], error)

	// EndSession handles the OpenID Connect RP-Initiated Logout.
	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
	EndSession(context.Context, *Request[oidc.EndSessionRequest]) (*Response[struct{}], error)

	// Keys serves the JWK set which the client can use verify signatures from the op.
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata `jwks_uri` key.
	Keys(context.Context, *Request[struct{}]) (*Response[jose.JSONWebKeySet], error)

	mustImpl()
}

type UnimplementedServer struct{}

// UnimplementedStatusCode is the statuscode returned for methods
// that are not yet implemented.
// Note that this means methods in the sense of the Go interface,
// and not http methods covered by "501 Not Implemented".
var UnimplementedStatusCode = http.StatusNotFound

func unimplementedError[T any](r *Request[T]) StatusError {
	err := oidc.ErrServerError().WithDescription(fmt.Sprintf("%s not implemented on this server", r.URL.Path))
	return StatusError{
		parent:     err,
		statusCode: UnimplementedStatusCode,
	}
}

func (UnimplementedServer) mustImpl() {}

func (UnimplementedServer) Health(_ context.Context, r *Request[struct{}]) (*Response[Status], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Ready(_ context.Context, r *Request[struct{}]) (*Response[Status], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Discovery(_ context.Context, r *Request[struct{}]) (*Response[oidc.DiscoveryConfiguration], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Authorize(_ context.Context, r *Request[oidc.AuthRequest]) (*Response[url.URL], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) DeviceAuthorization(_ context.Context, r *Request[oidc.DeviceAuthorizationRequest]) (*Response[oidc.DeviceAuthorizationResponse], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) VerifyClient(_ context.Context, r *Request[ClientCredentials]) (Client, error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) CodeExchange(_ context.Context, r *ClientRequest[oidc.AccessTokenRequest]) (*Response[oidc.AccessTokenResponse], error) {
	return nil, unimplementedError(r.Request)
}

func (UnimplementedServer) RefreshToken(_ context.Context, r *ClientRequest[oidc.RefreshTokenRequest]) (*Response[oidc.AccessTokenResponse], error) {
	return nil, unimplementedError(r.Request)
}

func (UnimplementedServer) JWTProfile(_ context.Context, r *Request[oidc.JWTProfileGrantRequest]) (*Response[oidc.AccessTokenResponse], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) TokenExchange(_ context.Context, r *ClientRequest[oidc.TokenExchangeRequest]) (*Response[oidc.AccessTokenResponse], error) {
	return nil, unimplementedError(r.Request)
}

func (UnimplementedServer) ClientCredentialsExchange(_ context.Context, r *ClientRequest[oidc.ClientCredentialsRequest]) (*Response[oidc.AccessTokenResponse], error) {
	return nil, unimplementedError(r.Request)
}

func (UnimplementedServer) DeviceToken(_ context.Context, r *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response[oidc.AccessTokenResponse], error) {
	return nil, unimplementedError(r.Request)
}

func (UnimplementedServer) Introspect(_ context.Context, r *Request[oidc.IntrospectionRequest]) (*Response[oidc.IntrospectionResponse], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) UserInfo(_ context.Context, r *Request[oidc.UserInfoRequest]) (*Response[oidc.UserInfo], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Revocation(_ context.Context, r *Request[oidc.RevocationRequest]) (*Response[struct{}], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) EndSession(_ context.Context, r *Request[oidc.EndSessionRequest]) (*Response[struct{}], error) {
	return nil, unimplementedError(r)
}

func (UnimplementedServer) Keys(_ context.Context, r *Request[struct{}]) (*Response[jose.JSONWebKeySet], error) {
	return nil, unimplementedError(r)
}

package op

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ExtendedLegacyServer allows embedding [LegacyServer] in a struct,
// so that its methods can be individually overridden.
//
// EXPERIMENTAL: may change until v4
type ExtendedLegacyServer interface {
	Server
	Provider() OpenIDProvider
	Endpoints() Endpoints
	AuthCallbackURL() func(context.Context, string) string
}

// RegisterLegacyServer registers a [LegacyServer] or an extension thereof.
// It takes care of registering the IssuerFromRequest middleware.
// The authorizeCallbackHandler is registered on `/callback` under the authorization endpoint.
// Neither are part of the bare [Server] interface.
//
// EXPERIMENTAL: may change until v4
func RegisterLegacyServer(s ExtendedLegacyServer, authorizeCallbackHandler http.HandlerFunc, options ...ServerOption) http.Handler {
	options = append(options,
		WithHTTPMiddleware(intercept(s.Provider().IssuerFromRequest)),
		WithSetRouter(func(r chi.Router) {
			r.HandleFunc(s.Endpoints().Authorization.Relative()+authCallbackPathSuffix, authorizeCallbackHandler)
		}),
	)
	return RegisterServer(s, s.Endpoints(), options...)
}

// LegacyServer is an implementation of [Server] that
// simply wraps an [OpenIDProvider].
// It can be used to transition from the former Provider/Storage
// interfaces to the new Server interface.
//
// EXPERIMENTAL: may change until v4
type LegacyServer struct {
	UnimplementedServer
	provider  OpenIDProvider
	endpoints Endpoints
}

// NewLegacyServer wraps provider in a `Server` implementation
//
// Only non-nil endpoints will be registered on the router.
// Nil endpoints are disabled.
//
// The passed endpoints is also used for the discovery config,
// and endpoints already set to the provider are ignored.
// Any `With*Endpoint()` option used on the provider is
// therefore ineffective.
//
// EXPERIMENTAL: may change until v4
func NewLegacyServer(provider OpenIDProvider, endpoints Endpoints) *LegacyServer {
	return &LegacyServer{
		provider:  provider,
		endpoints: endpoints,
	}
}

func (s *LegacyServer) Provider() OpenIDProvider {
	return s.provider
}

func (s *LegacyServer) Endpoints() Endpoints {
	return s.endpoints
}

// AuthCallbackURL builds the url for the redirect (with the requestID) after a successful login
func (s *LegacyServer) AuthCallbackURL() func(context.Context, string) string {
	return func(ctx context.Context, requestID string) string {
		ctx, span := tracer.Start(ctx, "LegacyServer.AuthCallbackURL")
		defer span.End()

		return s.endpoints.Authorization.Absolute(IssuerFromContext(ctx)) + authCallbackPathSuffix + "?id=" + requestID
	}
}

func (s *LegacyServer) Health(_ context.Context, r *Request[struct{}]) (*Response, error) {
	return NewResponse(Status{Status: "ok"}), nil
}

func (s *LegacyServer) Ready(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	for _, probe := range s.provider.Probes() {
		// shouldn't we run probes in Go routines?
		if err := probe(ctx); err != nil {
			return nil, AsStatusError(err, http.StatusInternalServerError)
		}
	}
	return NewResponse(Status{Status: "ok"}), nil
}

func (s *LegacyServer) Discovery(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.Discovery")
	defer span.End()

	return NewResponse(
		createDiscoveryConfigV2(ctx, s.provider, s.provider.Storage(), &s.endpoints),
	), nil
}

func (s *LegacyServer) Keys(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.Keys")
	defer span.End()

	keys, err := s.provider.Storage().KeySet(ctx)
	if err != nil {
		return nil, AsStatusError(err, http.StatusInternalServerError)
	}
	return NewResponse(jsonWebKeySet(keys)), nil
}

var (
	ErrAuthReqMissingClientID    = errors.New("auth request is missing client_id")
	ErrAuthReqMissingRedirectURI = errors.New("auth request is missing redirect_uri")
)

func (s *LegacyServer) VerifyAuthRequest(ctx context.Context, r *Request[oidc.AuthRequest]) (*ClientRequest[oidc.AuthRequest], error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.VerifyAuthRequest")
	defer span.End()

	if r.Data.RequestParam != "" {
		if !s.provider.RequestObjectSupported() {
			return nil, oidc.ErrRequestNotSupported()
		}
		err := ParseRequestObject(ctx, r.Data, s.provider.Storage(), IssuerFromContext(ctx))
		if err != nil {
			return nil, err
		}
	}
	if r.Data.ClientID == "" {
		return nil, oidc.ErrInvalidRequest().WithParent(ErrAuthReqMissingClientID).WithDescription(ErrAuthReqMissingClientID.Error())
	}
	client, err := s.provider.Storage().GetClientByClientID(ctx, r.Data.ClientID)
	if err != nil {
		return nil, oidc.DefaultToServerError(err, "unable to retrieve client by id")
	}

	return &ClientRequest[oidc.AuthRequest]{
		Request: r,
		Client:  client,
	}, nil
}

func (s *LegacyServer) Authorize(ctx context.Context, r *ClientRequest[oidc.AuthRequest]) (_ *Redirect, err error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.Authorize")
	defer span.End()

	userID, err := ValidateAuthReqIDTokenHint(ctx, r.Data.IDTokenHint, s.provider.IDTokenHintVerifier(ctx))
	if err != nil {
		return nil, err
	}
	req, err := s.provider.Storage().CreateAuthRequest(ctx, r.Data, userID)
	if err != nil {
		return TryErrorRedirect(ctx, r.Data, oidc.DefaultToServerError(err, "unable to save auth request"), s.provider.Encoder(), s.provider.Logger())
	}
	return NewRedirect(r.Client.LoginURL(req.GetID())), nil
}

func (s *LegacyServer) DeviceAuthorization(ctx context.Context, r *ClientRequest[oidc.DeviceAuthorizationRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.DeviceAuthorization")
	defer span.End()

	response, err := createDeviceAuthorization(ctx, r.Data, r.Client.GetID(), s.provider)
	if err != nil {
		return nil, AsStatusError(err, http.StatusInternalServerError)
	}
	return NewResponse(response), nil
}

func (s *LegacyServer) VerifyClient(ctx context.Context, r *Request[ClientCredentials]) (Client, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.VerifyClient")
	defer span.End()

	if oidc.GrantType(r.Form.Get("grant_type")) == oidc.GrantTypeClientCredentials {
		storage, ok := s.provider.Storage().(ClientCredentialsStorage)
		if !ok {
			return nil, oidc.ErrUnsupportedGrantType().WithDescription("client_credentials grant not supported")
		}
		return storage.ClientCredentials(ctx, r.Data.ClientID, r.Data.ClientSecret)
	}

	if r.Data.ClientAssertionType == oidc.ClientAssertionTypeJWTAssertion {
		jwtExchanger, ok := s.provider.(JWTAuthorizationGrantExchanger)
		if !ok || !s.provider.AuthMethodPrivateKeyJWTSupported() {
			return nil, oidc.ErrInvalidClient().WithDescription("auth_method private_key_jwt not supported")
		}
		return AuthorizePrivateJWTKey(ctx, r.Data.ClientAssertion, jwtExchanger)
	}
	client, err := s.provider.Storage().GetClientByClientID(ctx, r.Data.ClientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}

	switch client.AuthMethod() {
	case oidc.AuthMethodNone:
		return client, nil
	case oidc.AuthMethodPrivateKeyJWT:
		return nil, oidc.ErrInvalidClient().WithDescription("private_key_jwt not allowed for this client")
	case oidc.AuthMethodPost:
		if !s.provider.AuthMethodPostSupported() {
			return nil, oidc.ErrInvalidClient().WithDescription("auth_method post not supported")
		}
	}

	err = AuthorizeClientIDSecret(ctx, r.Data.ClientID, r.Data.ClientSecret, s.provider.Storage())
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (s *LegacyServer) CodeExchange(ctx context.Context, r *ClientRequest[oidc.AccessTokenRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.CodeExchange")
	defer span.End()

	authReq, err := AuthRequestByCode(ctx, s.provider.Storage(), r.Data.Code)
	if err != nil {
		return nil, err
	}
	if r.Client.AuthMethod() == oidc.AuthMethodNone || r.Data.CodeVerifier != "" {
		if err = AuthorizeCodeChallenge(r.Data.CodeVerifier, authReq.GetCodeChallenge()); err != nil {
			return nil, err
		}
	}
	if r.Data.RedirectURI != authReq.GetRedirectURI() {
		return nil, oidc.ErrInvalidGrant().WithDescription("redirect_uri does not correspond")
	}
	resp, err := CreateTokenResponse(ctx, authReq, r.Client, s.provider, true, r.Data.Code, "")
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) RefreshToken(ctx context.Context, r *ClientRequest[oidc.RefreshTokenRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.RefreshToken")
	defer span.End()

	if !s.provider.GrantTypeRefreshTokenSupported() {
		return nil, unimplementedGrantError(oidc.GrantTypeRefreshToken)
	}
	request, err := RefreshTokenRequestByRefreshToken(ctx, s.provider.Storage(), r.Data.RefreshToken)
	if err != nil {
		return nil, err
	}
	if r.Client.GetID() != request.GetClientID() {
		return nil, oidc.ErrInvalidGrant()
	}
	if err = ValidateRefreshTokenScopes(r.Data.Scopes, request); err != nil {
		return nil, err
	}
	resp, err := CreateTokenResponse(ctx, request, r.Client, s.provider, true, "", r.Data.RefreshToken)
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) JWTProfile(ctx context.Context, r *Request[oidc.JWTProfileGrantRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.JWTProfile")
	defer span.End()

	exchanger, ok := s.provider.(JWTAuthorizationGrantExchanger)
	if !ok {
		return nil, unimplementedGrantError(oidc.GrantTypeBearer)
	}
	tokenRequest, err := VerifyJWTAssertion(ctx, r.Data.Assertion, exchanger.JWTProfileVerifier(ctx))
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithParent(err).WithDescription("assertion invalid")
	}

	tokenRequest.Scopes, err = exchanger.Storage().ValidateJWTProfileScopes(ctx, tokenRequest.Issuer, r.Data.Scope)
	if err != nil {
		return nil, err
	}
	resp, err := CreateJWTTokenResponse(ctx, tokenRequest, exchanger)
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) TokenExchange(ctx context.Context, r *ClientRequest[oidc.TokenExchangeRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.TokenExchange")
	defer span.End()

	if !s.provider.GrantTypeTokenExchangeSupported() {
		return nil, unimplementedGrantError(oidc.GrantTypeTokenExchange)
	}
	tokenExchangeRequest, err := CreateTokenExchangeRequest(ctx, r.Data, r.Client, s.provider)
	if err != nil {
		return nil, err
	}
	resp, err := CreateTokenExchangeResponse(ctx, tokenExchangeRequest, r.Client, s.provider)
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) ClientCredentialsExchange(ctx context.Context, r *ClientRequest[oidc.ClientCredentialsRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.ClientCredentialsExchange")
	defer span.End()

	storage, ok := s.provider.Storage().(ClientCredentialsStorage)
	if !ok {
		return nil, unimplementedGrantError(oidc.GrantTypeClientCredentials)
	}
	tokenRequest, err := storage.ClientCredentialsTokenRequest(ctx, r.Client.GetID(), r.Data.Scope)
	if err != nil {
		return nil, err
	}
	resp, err := CreateClientCredentialsTokenResponse(ctx, tokenRequest, s.provider, r.Client)
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) DeviceToken(ctx context.Context, r *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.DeviceToken")
	defer span.End()

	if !s.provider.GrantTypeDeviceCodeSupported() {
		return nil, unimplementedGrantError(oidc.GrantTypeDeviceCode)
	}
	// use a limited context timeout shorter as the default
	// poll interval of 5 seconds.
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	tokenRequest, err := CheckDeviceAuthorizationState(ctx, r.Client.GetID(), r.Data.DeviceCode, s.provider)
	if err != nil {
		return nil, err
	}
	resp, err := CreateDeviceTokenResponse(ctx, tokenRequest, s.provider, r.Client)
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) authenticateResourceClient(ctx context.Context, cc *ClientCredentials) (string, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.authenticateResourceClient")
	defer span.End()

	if cc.ClientAssertion != "" {
		if jp, ok := s.provider.(ClientJWTProfile); ok {
			return ClientJWTAuth(ctx, oidc.ClientAssertionParams{ClientAssertion: cc.ClientAssertion}, jp)
		}
		return "", oidc.ErrInvalidClient().WithDescription("client_assertion not supported")
	}
	if err := s.provider.Storage().AuthorizeClientIDSecret(ctx, cc.ClientID, cc.ClientSecret); err != nil {
		return "", oidc.ErrUnauthorizedClient().WithParent(err)
	}
	return cc.ClientID, nil
}

func (s *LegacyServer) Introspect(ctx context.Context, r *Request[IntrospectionRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.Introspect")
	defer span.End()

	clientID, err := s.authenticateResourceClient(ctx, r.Data.ClientCredentials)
	if err != nil {
		return nil, err
	}
	response := new(oidc.IntrospectionResponse)
	tokenID, subject, ok := getTokenIDAndSubject(ctx, s.provider, r.Data.Token)
	if !ok {
		return NewResponse(response), nil
	}
	err = s.provider.Storage().SetIntrospectionFromToken(ctx, response, tokenID, subject, clientID)
	if err != nil {
		return NewResponse(response), nil
	}
	response.Active = true
	return NewResponse(response), nil
}

func (s *LegacyServer) UserInfo(ctx context.Context, r *Request[oidc.UserInfoRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.UserInfo")
	defer span.End()

	tokenID, subject, ok := getTokenIDAndSubject(ctx, s.provider, r.Data.AccessToken)
	if !ok {
		return nil, NewStatusError(oidc.ErrAccessDenied().WithDescription("access token invalid"), http.StatusUnauthorized)
	}
	info := new(oidc.UserInfo)
	err := s.provider.Storage().SetUserinfoFromToken(ctx, info, tokenID, subject, r.Header.Get("origin"))
	if err != nil {
		return nil, NewStatusError(err, http.StatusForbidden)
	}
	return NewResponse(info), nil
}

func (s *LegacyServer) Revocation(ctx context.Context, r *ClientRequest[oidc.RevocationRequest]) (*Response, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.Revocation")
	defer span.End()

	var subject string
	doDecrypt := true
	if r.Data.TokenTypeHint != "access_token" {
		userID, tokenID, err := s.provider.Storage().GetRefreshTokenInfo(ctx, r.Client.GetID(), r.Data.Token)
		if err != nil {
			// An invalid refresh token means that we'll try other things (leaving doDecrypt==true)
			if !errors.Is(err, ErrInvalidRefreshToken) {
				return nil, RevocationError(oidc.ErrServerError().WithParent(err))
			}
		} else {
			r.Data.Token = tokenID
			subject = userID
			doDecrypt = false
		}
	}
	if doDecrypt {
		tokenID, userID, ok := getTokenIDAndSubjectForRevocation(ctx, s.provider, r.Data.Token)
		if ok {
			r.Data.Token = tokenID
			subject = userID
		}
	}
	if err := s.provider.Storage().RevokeToken(ctx, r.Data.Token, subject, r.Client.GetID()); err != nil {
		return nil, RevocationError(err)
	}
	return NewResponse(nil), nil
}

func (s *LegacyServer) EndSession(ctx context.Context, r *Request[oidc.EndSessionRequest]) (*Redirect, error) {
	ctx, span := tracer.Start(ctx, "LegacyServer.EndSession")
	defer span.End()

	session, err := ValidateEndSessionRequest(ctx, r.Data, s.provider)
	if err != nil {
		return nil, err
	}
	redirect := session.RedirectURI
	if fromRequest, ok := s.provider.Storage().(CanTerminateSessionFromRequest); ok {
		redirect, err = fromRequest.TerminateSessionFromRequest(ctx, session)
	} else {
		err = s.provider.Storage().TerminateSession(ctx, session.UserID, session.ClientID)
	}
	if err != nil {
		return nil, err
	}
	return NewRedirect(redirect), nil
}

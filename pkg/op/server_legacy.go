package op

import (
	"context"
	"errors"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type LegacyServer struct {
	UnimplementedServer
	provider OpenIDProvider

	readyProbes []ProbesFn
}

func (s *LegacyServer) Health(_ context.Context, r *Request[struct{}]) (*Response, error) {
	return NewResponse(Status{Status: "ok"}), nil
}

func (s *LegacyServer) Ready(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	for _, probe := range s.readyProbes {
		// shouldn't we run probes in Go routines?
		if err := probe(ctx); err != nil {
			return nil, NewStatusError(err, http.StatusInternalServerError)
		}
	}
	return NewResponse(Status{Status: "ok"}), nil
}

func (s *LegacyServer) Discovery(ctx context.Context, r *Request[struct{}]) (*Response, error) {
	return NewResponse(
		CreateDiscoveryConfig(ctx, s.provider, s.provider.Storage()),
	), nil
}

var (
	ErrAuthReqMissingClientID    = errors.New("auth request is missing client_id")
	ErrAuthReqMissingRedirectURI = errors.New("auth request is missing redirect_uri")
)

func (s *LegacyServer) Authorize(ctx context.Context, r *Request[oidc.AuthRequest]) (_ *Redirect, err error) {
	authReq := r.Data
	if authReq.RequestParam != "" && s.provider.RequestObjectSupported() {
		authReq, err = ParseRequestObject(ctx, authReq, s.provider.Storage(), IssuerFromContext(ctx))
		if err != nil {
			return nil, NewStatusError(err, http.StatusBadRequest)
		}
	}
	if authReq.ClientID == "" {
		return TryErrorRedirect(ctx, authReq, ErrAuthReqMissingClientID, s.provider.Encoder(), s.provider.Logger())
	}
	if authReq.RedirectURI == "" {
		return TryErrorRedirect(ctx, authReq, ErrAuthReqMissingRedirectURI, s.provider.Encoder(), s.provider.Logger())
	}
	validation := ValidateAuthRequest
	if validater, ok := s.provider.(AuthorizeValidator); ok {
		validation = validater.ValidateAuthRequest
	}
	userID, err := validation(ctx, authReq, s.provider.Storage(), s.provider.IDTokenHintVerifier(ctx))
	if err != nil {
		return TryErrorRedirect(ctx, authReq, err, s.provider.Encoder(), s.provider.Logger())
	}
	if authReq.RequestParam != "" {
		return TryErrorRedirect(ctx, authReq, oidc.ErrRequestNotSupported(), s.provider.Encoder(), s.provider.Logger())
	}
	req, err := s.provider.Storage().CreateAuthRequest(ctx, authReq, userID)
	if err != nil {
		return TryErrorRedirect(ctx, authReq, oidc.DefaultToServerError(err, "unable to save auth request"), s.provider.Encoder(), s.provider.Logger())
	}
	client, err := s.provider.Storage().GetClientByClientID(ctx, req.GetClientID())
	if err != nil {
		return TryErrorRedirect(ctx, authReq, oidc.DefaultToServerError(err, "unable to retrieve client by id"), s.provider.Encoder(), s.provider.Logger())
	}
	return NewRedirect(client.LoginURL(req.GetID())), nil
}

func (s *LegacyServer) DeviceAuthorization(ctx context.Context, r *ClientRequest[oidc.DeviceAuthorizationRequest]) (*Response, error) {
	response, err := createDeviceAuthorization(ctx, r.Data, r.Client.GetID(), s.provider)
	if err != nil {
		return nil, NewStatusError(err, http.StatusInternalServerError)
	}
	return NewResponse(response), nil
}

func (s *LegacyServer) VerifyClient(ctx context.Context, r *Request[ClientCredentials]) (Client, error) {
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
	authReq, err := AuthRequestByCode(ctx, s.provider.Storage(), r.Data.Code)
	if err != nil {
		return nil, err
	}
	if r.Client.AuthMethod() == oidc.AuthMethodNone {
		if err = AuthorizeCodeChallenge(r.Data.CodeVerifier, authReq.GetCodeChallenge()); err != nil {
			return nil, err
		}
	}
	resp, err := CreateTokenResponse(ctx, authReq, r.Client, s.provider, true, r.Data.Code, "")
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) RefreshToken(ctx context.Context, r *ClientRequest[oidc.RefreshTokenRequest]) (*Response, error) {
	if !ValidateGrantType(r.Client, oidc.GrantTypeRefreshToken) {
		return nil, oidc.ErrUnauthorizedClient()
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

func (s *LegacyServer) JWTProfile(_ context.Context, r *Request[oidc.JWTProfileGrantRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (s *LegacyServer) TokenExchange(_ context.Context, r *ClientRequest[oidc.TokenExchangeRequest]) (*Response, error) {
	return nil, unimplementedError(r.Request)
}

func (s *LegacyServer) ClientCredentialsExchange(_ context.Context, r *ClientRequest[oidc.ClientCredentialsRequest]) (*Response, error) {
	return nil, unimplementedError(r.Request)
}

func (s *LegacyServer) DeviceToken(_ context.Context, r *ClientRequest[oidc.DeviceAccessTokenRequest]) (*Response, error) {
	return nil, unimplementedError(r.Request)
}

func (s *LegacyServer) Introspect(ctx context.Context, r *ClientRequest[oidc.IntrospectionRequest]) (*Response, error) {
	response := new(oidc.IntrospectionResponse)
	tokenID, subject, ok := getTokenIDAndSubject(ctx, s.provider, r.Data.Token)
	if !ok {
		return NewResponse(response), nil
	}
	err := s.provider.Storage().SetIntrospectionFromToken(ctx, response, tokenID, subject, r.Client.GetID())
	if err != nil {
		return NewResponse(response), nil
	}
	response.Active = true
	return NewResponse(response), nil
}

func (s *LegacyServer) UserInfo(ctx context.Context, r *Request[oidc.UserInfoRequest]) (*Response, error) {
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

func (s *LegacyServer) Revocation(_ context.Context, r *Request[oidc.RevocationRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (s *LegacyServer) EndSession(_ context.Context, r *Request[oidc.EndSessionRequest]) (*Response, error) {
	return nil, unimplementedError(r)
}

func (s *LegacyServer) Keys(_ context.Context, r *Request[struct{}]) (*Response, error) {
	return nil, unimplementedError(r)
}

package op

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type LegacyServer struct {
	UnimplementedServer
	op *Provider
}

func (s *LegacyServer) VerifyClient(ctx context.Context, r *Request[ClientCredentials]) (Client, error) {
	if r.Data.ClientAssertionType == oidc.ClientAssertionTypeJWTAssertion {
		if !s.op.AuthMethodPrivateKeyJWTSupported() {
			return nil, oidc.ErrInvalidClient().WithDescription("auth_method private_key_jwt not supported")
		}
		return AuthorizePrivateJWTKey(ctx, r.Data.ClientAssertion, s.op)
	}
	client, err := s.op.Storage().GetClientByClientID(ctx, r.Data.ClientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}

	switch client.AuthMethod() {
	case oidc.AuthMethodNone:
		return client, nil
	case oidc.AuthMethodPrivateKeyJWT:
		return nil, oidc.ErrInvalidClient().WithDescription("private_key_jwt not allowed for this client")
	case oidc.AuthMethodPost:
		if !s.op.AuthMethodPostSupported() {
			return nil, oidc.ErrInvalidClient().WithDescription("auth_method post not supported")
		}
	}

	err = AuthorizeClientIDSecret(ctx, r.Data.ClientID, r.Data.ClientSecret, s.op.storage)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (s *LegacyServer) CodeExchange(ctx context.Context, r *ClientRequest[oidc.AccessTokenRequest]) (*Response[oidc.AccessTokenResponse], error) {
	authReq, err := AuthRequestByCode(ctx, s.op.storage, r.Data.Code)
	if err != nil {
		return nil, err
	}
	if r.Client.AuthMethod() == oidc.AuthMethodNone {
		if err = AuthorizeCodeChallenge(r.Data.CodeVerifier, authReq.GetCodeChallenge()); err != nil {
			return nil, err
		}
	}
	resp, err := CreateTokenResponse(ctx, authReq, r.Client, s.op, true, r.Data.Code, "")
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (s *LegacyServer) RefreshToken(ctx context.Context, r *ClientRequest[oidc.RefreshTokenRequest]) (*Response[oidc.AccessTokenResponse], error) {
	if !ValidateGrantType(r.Client, oidc.GrantTypeRefreshToken) {
		return nil, oidc.ErrUnauthorizedClient()
	}
	request, err := RefreshTokenRequestByRefreshToken(ctx, s.op.storage, r.Data.RefreshToken)
	if err != nil {
		return nil, err
	}
	if r.Client.GetID() != request.GetClientID() {
		return nil, oidc.ErrInvalidGrant()
	}
	if err = ValidateRefreshTokenScopes(r.Data.Scopes, request); err != nil {
		return nil, err
	}
	resp, err := CreateTokenResponse(ctx, request, r.Client, s.op, true, "", r.Data.RefreshToken)
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

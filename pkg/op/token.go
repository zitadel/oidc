package op

import (
	"context"
	"time"

	"github.com/caos/oidc/pkg/oidc"
)

type TokenCreator interface {
	Issuer() string
	Signer() Signer
	Storage() Storage
	Crypto() Crypto
}

type TokenRequest interface {
	GetSubject() string
	GetAudience() []string
	GetScopes() []string
}

func CreateTokenResponse(ctx context.Context, authReq AuthRequest, client Client, creator TokenCreator, createAccessToken bool, code string) (*oidc.AccessTokenResponse, error) {
	var accessToken string
	var validity time.Duration
	if createAccessToken {
		var err error
		accessToken, validity, err = CreateAccessToken(ctx, authReq, client.AccessTokenType(), creator)
		if err != nil {
			return nil, err
		}
	}
	idToken, err := CreateIDToken(ctx, creator.Issuer(), authReq, client.IDTokenLifetime(), accessToken, code, creator.Storage(), creator.Signer())
	if err != nil {
		return nil, err
	}

	err = creator.Storage().DeleteAuthRequest(ctx, authReq.GetID())
	if err != nil {
		return nil, err
	}

	exp := uint64(validity.Seconds())
	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   exp,
	}, nil
}

func CreateJWTTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator) (*oidc.AccessTokenResponse, error) {
	accessToken, validity, err := CreateAccessToken(ctx, tokenRequest, AccessTokenTypeBearer, creator)
	if err != nil {
		return nil, err
	}

	exp := uint64(validity.Seconds())
	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   exp,
	}, nil
}

func CreateAccessToken(ctx context.Context, authReq TokenRequest, accessTokenType AccessTokenType, creator TokenCreator) (token string, validity time.Duration, err error) {
	id, exp, err := creator.Storage().CreateToken(ctx, authReq)
	if err != nil {
		return "", 0, err
	}
	validity = exp.Sub(time.Now().UTC())
	if accessTokenType == AccessTokenTypeJWT {
		token, err = CreateJWT(creator.Issuer(), authReq, exp, id, creator.Signer())
		return
	}
	token, err = CreateBearerToken(id, authReq.GetSubject(), creator.Crypto())
	return
}

func CreateBearerToken(tokenID, subject string, crypto Crypto) (string, error) {
	return crypto.Encrypt(tokenID + ":" + subject)
}

func CreateJWT(issuer string, authReq TokenRequest, exp time.Time, id string, signer Signer) (string, error) {
	now := time.Now().UTC()
	nbf := now
	claims := &oidc.AccessTokenClaims{
		Issuer:     issuer,
		Subject:    authReq.GetSubject(),
		Audiences:  authReq.GetAudience(),
		Expiration: exp,
		IssuedAt:   now,
		NotBefore:  nbf,
		JWTID:      id,
	}
	return signer.SignAccessToken(claims)
}

func CreateIDToken(ctx context.Context, issuer string, authReq AuthRequest, validity time.Duration, accessToken, code string, storage Storage, signer Signer) (string, error) {
	var err error
	exp := time.Now().UTC().Add(validity)
	userinfo, err := storage.GetUserinfoFromScopes(ctx, authReq.GetSubject(), authReq.GetScopes())
	if err != nil {
		return "", err
	}
	claims := &oidc.IDTokenClaims{
		Issuer:                              issuer,
		Audiences:                           authReq.GetAudience(),
		Expiration:                          exp,
		IssuedAt:                            time.Now().UTC(),
		AuthTime:                            authReq.GetAuthTime(),
		Nonce:                               authReq.GetNonce(),
		AuthenticationContextClassReference: authReq.GetACR(),
		AuthenticationMethodsReferences:     authReq.GetAMR(),
		AuthorizedParty:                     authReq.GetClientID(),
		Userinfo:                            *userinfo,
	}
	if accessToken != "" {
		claims.AccessTokenHash, err = oidc.ClaimHash(accessToken, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
	}
	if code != "" {
		claims.CodeHash, err = oidc.ClaimHash(code, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
	}

	return signer.SignIDToken(claims)
}

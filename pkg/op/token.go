package op

import (
	"context"
	"time"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
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
	token, err = CreateBearerToken(id, creator.Crypto())
	return
}

func CreateBearerToken(id string, crypto Crypto) (string, error) {
	return crypto.Encrypt(id)
}

func CreateJWT(issuer string, tokenRequest TokenRequest, exp time.Time, id string, signer Signer) (string, error) {
	claims := oidc.NewAccessTokenClaims(issuer, tokenRequest.GetSubject(), tokenRequest.GetAudience(), exp, id)
	return utils.Sign(claims, signer.Signer())
}

func CreateIDToken(ctx context.Context, issuer string, authReq AuthRequest, validity time.Duration, accessToken, code string, storage Storage, signer Signer) (string, error) {
	exp := time.Now().UTC().Add(validity)
	claims := oidc.NewIDTokenClaims(issuer, authReq.GetSubject(), authReq.GetAudience(), exp, authReq.GetAuthTime(), authReq.GetNonce(), authReq.GetACR(), authReq.GetAMR(), authReq.GetClientID())

	if accessToken != "" {
		atHash, err := oidc.ClaimHash(accessToken, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.SetAccessTokenHash(atHash)
	} else {
		userInfo, err := storage.GetUserinfoFromScopes(ctx, authReq.GetSubject(), authReq.GetClientID(), authReq.GetScopes())
		if err != nil {
			return "", err
		}
		claims.SetUserinfo(userInfo)
	}
	if code != "" {
		codeHash, err := oidc.ClaimHash(code, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.SetCodeHash(codeHash)
	}

	return utils.Sign(claims, signer.Signer())
}

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
		accessToken, validity, err = CreateAccessToken(ctx, authReq, client.AccessTokenType(), creator, client)
		if err != nil {
			return nil, err
		}
	}
	idToken, err := CreateIDToken(ctx, creator.Issuer(), authReq, client.IDTokenLifetime(), accessToken, code, creator.Storage(), creator.Signer(), client.AssertAdditionalIdTokenScopes())
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
	accessToken, validity, err := CreateAccessToken(ctx, tokenRequest, AccessTokenTypeBearer, creator, nil)
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

func CreateAccessToken(ctx context.Context, tokenRequest TokenRequest, accessTokenType AccessTokenType, creator TokenCreator, client Client) (token string, validity time.Duration, err error) {
	id, exp, err := creator.Storage().CreateToken(ctx, tokenRequest)
	if err != nil {
		return "", 0, err
	}
	validity = exp.Sub(time.Now().UTC())
	if accessTokenType == AccessTokenTypeJWT {
		token, err = CreateJWT(ctx, creator.Issuer(), tokenRequest, exp, id, creator.Signer(), client, creator.Storage())
		return
	}
	token, err = CreateBearerToken(id, creator.Crypto())
	return
}

func CreateBearerToken(id string, crypto Crypto) (string, error) {
	return crypto.Encrypt(id)
}

func CreateJWT(ctx context.Context, issuer string, tokenRequest TokenRequest, exp time.Time, id string, signer Signer, client Client, storage Storage) (string, error) {
	claims := oidc.NewAccessTokenClaims(issuer, tokenRequest.GetSubject(), tokenRequest.GetAudience(), exp, id)
	if client != nil && client.AssertAdditionalAccessTokenScopes() {
		privateClaims, err := storage.GetPrivateClaimsFromScopes(ctx, tokenRequest.GetSubject(), client.GetID(), removeUserinfoScopes(tokenRequest.GetScopes()))
		if err != nil {
			return "", err
		}
		claims.SetPrivateClaims(privateClaims)
	}
	return utils.Sign(claims, signer.Signer())
}

func CreateIDToken(ctx context.Context, issuer string, authReq AuthRequest, validity time.Duration, accessToken, code string, storage Storage, signer Signer, additonalScopes bool) (string, error) {
	exp := time.Now().UTC().Add(validity)
	claims := oidc.NewIDTokenClaims(issuer, authReq.GetSubject(), authReq.GetAudience(), exp, authReq.GetAuthTime(), authReq.GetNonce(), authReq.GetACR(), authReq.GetAMR(), authReq.GetClientID())
	scopes := authReq.GetScopes()

	if accessToken != "" {
		atHash, err := oidc.ClaimHash(accessToken, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.SetAccessTokenHash(atHash)
		scopes = removeUserinfoScopes(scopes)
	}
	if !additonalScopes {
		scopes = removeAdditionalScopes(scopes)
	}
	if len(scopes) > 0 {
		userInfo, err := storage.GetUserinfoFromScopes(ctx, authReq.GetSubject(), authReq.GetClientID(), scopes)
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

func removeUserinfoScopes(scopes []string) []string {
	for i := len(scopes) - 1; i >= 0; i-- {
		if scopes[i] == oidc.ScopeProfile ||
			scopes[i] == oidc.ScopeEmail ||
			scopes[i] == oidc.ScopeAddress ||
			scopes[i] == oidc.ScopePhone {

			scopes[i] = scopes[len(scopes)-1]
			scopes[len(scopes)-1] = ""
			scopes = scopes[:len(scopes)-1]
		}
	}
	return scopes
}

func removeAdditionalScopes(scopes []string) []string {
	for i := len(scopes) - 1; i >= 0; i-- {
		if !(scopes[i] == oidc.ScopeOpenID ||
			scopes[i] == oidc.ScopeProfile ||
			scopes[i] == oidc.ScopeEmail ||
			scopes[i] == oidc.ScopeAddress ||
			scopes[i] == oidc.ScopePhone) {

			scopes[i] = scopes[len(scopes)-1]
			scopes[len(scopes)-1] = ""
			scopes = scopes[:len(scopes)-1]
		}
	}
	return scopes
}

package op

import (
	"time"

	"github.com/caos/oidc/pkg/oidc"
)

type TokenCreator interface {
	Issuer() string
	Signer() Signer
	Storage() Storage
	Crypto() Crypto
}

func CreateTokenResponse(authReq AuthRequest, client Client, creator TokenCreator, createAccessToken bool, code string) (*oidc.AccessTokenResponse, error) {
	var accessToken string
	if createAccessToken {
		var err error
		accessToken, err = CreateAccessToken(authReq, client, creator)
		if err != nil {
			return nil, err
		}
	}
	idToken, err := CreateIDToken(creator.Issuer(), authReq, client.IDTokenLifetime(), accessToken, code, creator.Signer())
	if err != nil {
		return nil, err
	}
	exp := uint64(client.AccessTokenLifetime().Seconds())
	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   exp,
	}, nil
}

func CreateAccessToken(authReq AuthRequest, client Client, creator TokenCreator) (string, error) {
	if client.AccessTokenType() == AccessTokenTypeJWT {
		return CreateJWT(creator.Issuer(), authReq, client, creator.Signer())
	}
	return CreateBearerToken(authReq, creator.Crypto())
}

func CreateBearerToken(authReq AuthRequest, crypto Crypto) (string, error) {
	return crypto.Encrypt(authReq.GetID())
}

func CreateJWT(issuer string, authReq AuthRequest, client Client, signer Signer) (string, error) {
	now := time.Now().UTC()
	nbf := now
	exp := now.Add(client.AccessTokenLifetime())
	claims := &oidc.AccessTokenClaims{
		Issuer:     issuer,
		Subject:    authReq.GetSubject(),
		Audiences:  authReq.GetAudience(),
		Expiration: exp,
		IssuedAt:   now,
		NotBefore:  nbf,
	}
	return signer.SignAccessToken(claims)
}

func CreateIDToken(issuer string, authReq AuthRequest, validity time.Duration, accessToken, code string, signer Signer) (string, error) {
	var err error
	exp := time.Now().UTC().Add(validity)
	claims := &oidc.IDTokenClaims{
		Issuer:                              issuer,
		Subject:                             authReq.GetSubject(),
		Audiences:                           authReq.GetAudience(),
		Expiration:                          exp,
		IssuedAt:                            time.Now().UTC(),
		AuthTime:                            authReq.GetAuthTime(),
		Nonce:                               authReq.GetNonce(),
		AuthenticationContextClassReference: authReq.GetACR(),
		AuthenticationMethodsReferences:     authReq.GetAMR(),
		AuthorizedParty:                     authReq.GetClientID(),
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

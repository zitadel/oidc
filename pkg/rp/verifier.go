package rp

import (
	"context"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
)

//deprecated: Use IDTokenVerifier or oidc.Verifier
type Verifier interface {

	//Verify checks the access_token and id_token and returns the `id token claims`
	Verify(ctx context.Context, accessToken, idTokenString string) (*oidc.IDTokenClaims, error)

	//VerifyIDToken checks the id_token only and returns its `id token claims`
	VerifyIDToken(ctx context.Context, idTokenString string) (*oidc.IDTokenClaims, error)
}

type IDTokenVerifier interface {
	oidc.Verifier
}

//VerifyTokens implement the Token Response Validation as defined in OIDC specification
//https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
func VerifyTokens(ctx context.Context, accessToken, idTokenString string, v IDTokenVerifier) (*oidc.IDTokenClaims, error) {
	idToken, err := VerifyIDToken(ctx, idTokenString, v)
	if err != nil {
		return nil, err
	}
	if err := VerifyAccessToken(accessToken, idToken.AccessTokenHash, idToken.Signature); err != nil {
		return nil, err
	}
	return idToken, nil
}

//VerifyIDToken validates the id token according to
//https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func VerifyIDToken(ctx context.Context, token string, v IDTokenVerifier) (*oidc.IDTokenClaims, error) {
	claims := new(oidc.IDTokenClaims)

	decrypted, err := oidc.DecryptToken(token)
	if err != nil {
		return nil, err
	}
	payload, err := oidc.ParseToken(decrypted, claims)
	if err != nil {
		return nil, err
	}
	//2, check issuer (exact match)
	if err := oidc.CheckIssuer(claims.GetIssuer(), v); err != nil {
		return nil, err
	}

	//3. check aud (aud must contain client_id, all aud strings must be allowed)
	if err = oidc.CheckAudience(claims.GetAudience(), v); err != nil {
		return nil, err
	}

	if err = oidc.CheckAuthorizedParty(claims.GetAudience(), claims.GetAuthorizedParty(), v); err != nil {
		return nil, err
	}

	//6. check signature by keys
	//7. check alg default is rs256
	//8. check if alg is mac based (hs...) -> audience contains client_id. for validation use utf-8 representation of your client_secret
	if err = oidc.CheckSignature(ctx, decrypted, payload, claims, v); err != nil {
		return nil, err
	}

	//9. check exp before now
	if err = oidc.CheckExpiration(claims.GetExpiration(), v); err != nil {
		return nil, err
	}

	//10. check iat duration is optional (can be checked)
	if err = oidc.CheckIssuedAt(claims.GetIssuedAt(), v); err != nil {
		return nil, err
	}

	/*
		//11. check nonce (check if optional possible) id_token.nonce == sentNonce
		if err = oidc.CheckNonce(claims.GetNonce()); err != nil {
			return nil, err
		}
	*/

	//12. if acr requested check acr
	if err = oidc.CheckAuthorizationContextClassReference(claims.GetAuthenticationContextClassReference(), v); err != nil {
		return nil, err
	}

	//13. if auth_time requested check if auth_time is less than max age
	if err = oidc.CheckAuthTime(claims.GetAuthTime(), v); err != nil {
		return nil, err
	}
	return claims, nil
}

//VerifyAccessToken validates the access token according to
//https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
func VerifyAccessToken(accessToken, atHash string, sigAlgorithm jose.SignatureAlgorithm) error {
	if atHash == "" {
		return nil
	}

	actual, err := oidc.ClaimHash(accessToken, sigAlgorithm)
	if err != nil {
		return err
	}
	if actual != atHash {
		return oidc.ErrAtHash
	}
	return nil
}

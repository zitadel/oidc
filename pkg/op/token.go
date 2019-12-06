package op

import (
	"fmt"
	"time"

	"github.com/caos/oidc/pkg/oidc"
)

func CreateAccessToken(authReq AuthRequest, signer Signer) (string, uint64, error) {
	var err error
	accessToken := fmt.Sprintf("%s:%s:%s:%s", authReq.GetSubject(), authReq.GetClientID(), authReq.GetAudience(), authReq.GetScopes())
	exp := time.Duration(5 * time.Minute)
	return accessToken, uint64(exp.Seconds()), err
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

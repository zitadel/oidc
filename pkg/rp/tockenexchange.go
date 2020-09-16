package rp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/oidc/grants/tokenexchange"
)

//TokenExchangeRP extends the `RelayingParty` interface for the *draft* oauth2 `Token Exchange`
type TokenExchangeRP interface {
	RelayingParty

	//TokenExchange implement the `Token Exchange Grant` exchanging some token for an other
	TokenExchange(context.Context, *tokenexchange.TokenExchangeRequest) (*oauth2.Token, error)
}

//DelegationTokenExchangeRP extends the `TokenExchangeRP` interface
//for the specific `delegation token` request
type DelegationTokenExchangeRP interface {
	TokenExchangeRP

	//DelegationTokenExchange implement the `Token Exchange Grant`
	//providing an access token in request for a `delegation` token for a given resource / audience
	DelegationTokenExchange(context.Context, string, ...tokenexchange.TokenExchangeOption) (*oauth2.Token, error)
}

//TokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange (draft)
func TokenExchange(ctx context.Context, request *tokenexchange.TokenExchangeRequest, rp RelayingParty) (newToken *oauth2.Token, err error) {
	return CallTokenEndpoint(request, rp)
}

//DelegationTokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange for a delegation token (draft)
func DelegationTokenExchange(ctx context.Context, subjectToken string, rp RelayingParty, reqOpts ...tokenexchange.TokenExchangeOption) (newToken *oauth2.Token, err error) {
	return TokenExchange(ctx, DelegationTokenRequest(subjectToken, reqOpts...), rp)
}

func JWTProfileExchange(ctx context.Context, assertion *oidc.JWTProfileAssertion, rp RelayingParty) (*oauth2.Token, error) {
	token, err := generateJWTProfileToken(assertion)
	if err != nil {
		return nil, err
	}
	return CallJWTProfileEndpoint(token, rp)
}

func generateJWTProfileToken(assertion *oidc.JWTProfileAssertion) (string, error) {
	privateKey, err := bytesToPrivateKey(assertion.PrivateKey)
	if err != nil {
		return "", err
	}
	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       &jose.JSONWebKey{Key: privateKey, KeyID: assertion.PrivateKeyID},
	}
	signer, err := jose.NewSigner(key, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}

	marshalledAssertion, err := json.Marshal(assertion)
	if err != nil {
		return "", err
	}
	signedAssertion, err := signer.Sign(marshalledAssertion)
	if err != nil {
		return "", err
	}
	return signedAssertion.CompactSerialize()
}

func bytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

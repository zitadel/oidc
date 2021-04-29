package op

import (
	"context"
	"net/http"
	"net/url"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type Exchanger interface {
	Issuer() string
	Storage() Storage
	Decoder() utils.Decoder
	Signer() Signer
	Crypto() Crypto
	AuthMethodPostSupported() bool
	AuthMethodPrivateKeyJWTSupported() bool
	GrantTypeTokenExchangeSupported() bool
	GrantTypeJWTAuthorizationSupported() bool
}

func tokenHandler(exchanger Exchanger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.FormValue("grant_type") {
		case string(oidc.GrantTypeCode):
			CodeExchange(w, r, exchanger)
			return
		case string(oidc.GrantTypeRefreshToken):
			RefreshTokenExchange(w, r, exchanger)
			return
		case string(oidc.GrantTypeBearer):
			if ex, ok := exchanger.(JWTAuthorizationGrantExchanger); ok && exchanger.GrantTypeJWTAuthorizationSupported() {
				JWTProfile(w, r, ex)
				return
			}
		case string(oidc.GrantTypeTokenExchange):
			if exchanger.GrantTypeTokenExchangeSupported() {
				TokenExchange(w, r, exchanger)
				return
			}
		case "":
			RequestError(w, r, ErrInvalidRequest("grant_type missing"))
			return
		}
		RequestError(w, r, ErrInvalidRequest("grant_type not supported"))
	}
}

//authenticatedTokenRequest is a helper interface for ParseAuthenticatedTokenRequest
//it is implemented by oidc.AuthRequest and oidc.RefreshTokenRequest
type AuthenticatedTokenRequest interface {
	SetClientID(string)
	SetClientSecret(string)
}

//ParseAuthenticatedTokenRequest parses the client_id and client_secret from the HTTP request from either
//HTTP Basic Auth header or form body and sets them into the provided authenticatedTokenRequest interface
func ParseAuthenticatedTokenRequest(r *http.Request, decoder utils.Decoder, request AuthenticatedTokenRequest) error {
	err := r.ParseForm()
	if err != nil {
		return ErrInvalidRequest("error parsing form")
	}
	err = decoder.Decode(request, r.Form)
	if err != nil {
		return ErrInvalidRequest("error decoding form")
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		clientID, err = url.QueryUnescape(clientID)
		if err != nil {
			return ErrInvalidRequest("invalid basic auth header")
		}
		clientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			return ErrInvalidRequest("invalid basic auth header")
		}
		request.SetClientID(clientID)
		request.SetClientSecret(clientSecret)
	}
	return nil
}

//AuthorizeRefreshClientByClientIDSecret authorizes a client by validating the client_id and client_secret (Basic Auth and POST)
func AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string, storage Storage) error {
	err := storage.AuthorizeClientIDSecret(ctx, clientID, clientSecret)
	if err != nil {
		return err //TODO: wrap?
	}
	return nil
}

//AuthorizeCodeClientByCodeChallenge authorizes a client by validating the code_verifier against the previously sent
//code_challenge of the auth request (PKCE)
func AuthorizeCodeChallenge(tokenReq *oidc.AccessTokenRequest, challenge *oidc.CodeChallenge) error {
	if tokenReq.CodeVerifier == "" {
		return ErrInvalidRequest("code_challenge required")
	}
	if !oidc.VerifyCodeChallenge(challenge, tokenReq.CodeVerifier) {
		return ErrInvalidRequest("code_challenge invalid")
	}
	return nil
}

//AuthorizePrivateJWTKey authorizes a client by validating the client_assertion's signature with a previously
//registered public key (JWT Profile)
func AuthorizePrivateJWTKey(ctx context.Context, clientAssertion string, exchanger JWTAuthorizationGrantExchanger) (Client, error) {
	jwtReq, err := VerifyJWTAssertion(ctx, clientAssertion, exchanger.JWTProfileVerifier())
	if err != nil {
		return nil, err
	}
	client, err := exchanger.Storage().GetClientByClientID(ctx, jwtReq.Issuer)
	if err != nil {
		return nil, err
	}
	if client.AuthMethod() != oidc.AuthMethodPrivateKeyJWT {
		return nil, ErrInvalidRequest("invalid_client")
	}
	return client, nil
}

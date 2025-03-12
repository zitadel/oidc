package op

import (
	"context"
	"net/http"
	"net/url"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ClientCredentialsExchange handles the OAuth 2.0 client_credentials grant, including
// parsing, validating, authorizing the client and finally returning a token
func ClientCredentialsExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	ctx, span := tracer.Start(r.Context(), "ClientCredentialsExchange")
	defer span.End()
	r = r.WithContext(ctx)

	request, err := ParseClientCredentialsRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
	}

	validatedRequest, client, err := ValidateClientCredentialsRequest(r.Context(), request, exchanger)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}

	resp, err := CreateClientCredentialsTokenResponse(r.Context(), validatedRequest, exchanger, client)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}

	httphelper.MarshalJSON(w, resp)
}

// ParseClientCredentialsRequest parsed the http request into a oidc.ClientCredentialsRequest
func ParseClientCredentialsRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.ClientCredentialsRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	request := new(oidc.ClientCredentialsRequest)
	err = decoder.Decode(request, r.Form)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}

	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		clientID, err = url.QueryUnescape(clientID)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}

		clientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}

		request.ClientID = clientID
		request.ClientSecret = clientSecret
	}

	return request, nil
}

// ValidateClientCredentialsRequest validates the client_credentials request parameters including authorization check of the client
// and returns a TokenRequest and Client implementation to be used in the client_credentials response, resp. creation of the corresponding access_token.
func ValidateClientCredentialsRequest(ctx context.Context, request *oidc.ClientCredentialsRequest, exchanger Exchanger) (TokenRequest, Client, error) {
	ctx, span := tracer.Start(ctx, "ValidateClientCredentialsRequest")
	defer span.End()

	storage, ok := exchanger.Storage().(ClientCredentialsStorage)
	if !ok {
		return nil, nil, oidc.ErrUnsupportedGrantType().WithDescription("client_credentials grant not supported")
	}

	client, err := AuthorizeClientCredentialsClient(ctx, request, storage)
	if err != nil {
		return nil, nil, err
	}

	tokenRequest, err := storage.ClientCredentialsTokenRequest(ctx, request.ClientID, request.Scope)
	if err != nil {
		return nil, nil, err
	}

	return tokenRequest, client, nil
}

func AuthorizeClientCredentialsClient(ctx context.Context, request *oidc.ClientCredentialsRequest, storage ClientCredentialsStorage) (Client, error) {
	ctx, span := tracer.Start(ctx, "AuthorizeClientCredentialsClient")
	defer span.End()

	client, err := storage.ClientCredentials(ctx, request.ClientID, request.ClientSecret)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}

	if !ValidateGrantType(client, oidc.GrantTypeClientCredentials) {
		return nil, oidc.ErrUnauthorizedClient()
	}

	return client, nil
}

func CreateClientCredentialsTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator, client Client) (*oidc.AccessTokenResponse, error) {
	ctx, span := tracer.Start(ctx, "CreateClientCredentialsTokenResponse")
	defer span.End()

	accessToken, _, validity, err := CreateAccessToken(ctx, tokenRequest, client.AccessTokenType(), creator, client, "")
	if err != nil {
		return nil, err
	}

	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(validity.Seconds()),
		Scope:       tokenRequest.GetScopes(),
	}, nil
}

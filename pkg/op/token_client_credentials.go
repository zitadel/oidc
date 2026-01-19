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
	ctx, span := Tracer.Start(r.Context(), "ClientCredentialsExchange")
	defer span.End()
	r = r.WithContext(ctx)

	request, err := ParseClientCredentialsRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}

	var (
		validatedRequest TokenRequest
		client           Client
	)

	// mTLS client authentication for client_credentials (RFC 8705)
	// Unlike other flows, this handler doesn't use ClientIDFromRequest, so we must validate here.
	if mtls, ok := exchanger.(mtlsClientCredentialsSupport); ok && request.ClientID != "" &&
		(mtls.AuthMethodTLSClientAuthSupported() || mtls.AuthMethodSelfSignedTLSClientAuthSupported()) {
		c, err := exchanger.Storage().GetClientByClientID(r.Context(), request.ClientID)
		if err == nil && (c.AuthMethod() == oidc.AuthMethodTLSClientAuth || c.AuthMethod() == oidc.AuthMethodSelfSignedTLSClientAuth) {
			validatedRequest, client, err = validateClientCredentialsRequestMTLS(r.Context(), r, request, exchanger, c)
			if err != nil {
				RequestError(w, r, err, exchanger.Logger())
				return
			}
		}
	}

	if validatedRequest == nil {
		validatedRequest, client, err = ValidateClientCredentialsRequest(r.Context(), request, exchanger)
		if err != nil {
			RequestError(w, r, err, exchanger.Logger())
			return
		}
	}

	// Set certificate thumbprint in context for certificate-bound tokens (RFC 8705)
	tokenCtx := r.Context()
	if mtlsProvider, ok := exchanger.(interface{ MTLSConfig() *MTLSConfig }); ok {
		boundSupported := false
		if s, ok := exchanger.(interface{ TLSClientCertificateBoundAccessTokensSupported() bool }); ok {
			boundSupported = s.TLSClientCertificateBoundAccessTokensSupported()
		}
		tokenCtx, err = SetCertThumbprintInContext(tokenCtx, r, client, mtlsProvider.MTLSConfig(), boundSupported)
		if err != nil {
			RequestError(w, r, err, exchanger.Logger())
			return
		}
	}
	resp, err := CreateClientCredentialsTokenResponse(tokenCtx, validatedRequest, exchanger, client)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}

	httphelper.MarshalJSON(w, resp)
}

type mtlsClientCredentialsSupport interface {
	MTLSConfig() *MTLSConfig
	AuthMethodTLSClientAuthSupported() bool
	AuthMethodSelfSignedTLSClientAuthSupported() bool
}

func validateClientCredentialsRequestMTLS(ctx context.Context, r *http.Request, request *oidc.ClientCredentialsRequest, exchanger Exchanger, client Client) (TokenRequest, Client, error) {
	storage, ok := exchanger.Storage().(ClientCredentialsStorage)
	if !ok {
		return nil, nil, oidc.ErrUnsupportedGrantType().WithDescription("client_credentials grant not supported")
	}
	mtls, ok := exchanger.(mtlsClientCredentialsSupport)
	if !ok {
		return nil, nil, oidc.ErrInvalidClient().WithDescription("mTLS authentication not supported")
	}
	mtlsConfig := mtls.MTLSConfig()

	certs, err := ClientCertificateFromRequest(r, mtlsConfig)
	if err != nil || len(certs) == 0 {
		return nil, nil, oidc.ErrInvalidClient().WithDescription("no client certificate provided")
	}

	switch client.AuthMethod() {
	case oidc.AuthMethodTLSClientAuth:
		if !mtls.AuthMethodTLSClientAuthSupported() {
			return nil, nil, oidc.ErrInvalidClient().WithDescription("tls_client_auth not supported")
		}
		mtlsClient, ok := client.(HasMTLSConfig)
		if !ok {
			return nil, nil, oidc.ErrInvalidClient().WithDescription("client does not support mTLS configuration")
		}
		if err := ValidateTLSClientAuth(certs, mtlsConfig, mtlsClient.GetMTLSConfig()); err != nil {
			return nil, nil, oidc.ErrInvalidClient().WithDescription("mTLS client authentication failed").WithParent(err)
		}

	case oidc.AuthMethodSelfSignedTLSClientAuth:
		if !mtls.AuthMethodSelfSignedTLSClientAuthSupported() {
			return nil, nil, oidc.ErrInvalidClient().WithDescription("self_signed_tls_client_auth not supported")
		}
		selfSignedClient, ok := client.(HasSelfSignedCertificate)
		if !ok {
			return nil, nil, oidc.ErrInvalidClient().WithDescription("client does not support self-signed certificates")
		}
		if err := ValidateSelfSignedTLSClientAuth(certs[0], selfSignedClient.GetRegisteredCertificates()); err != nil {
			return nil, nil, oidc.ErrInvalidClient().WithDescription("mTLS client authentication failed").WithParent(err)
		}

	default:
		return nil, nil, oidc.ErrInvalidClient()
	}

	if !ValidateGrantType(client, oidc.GrantTypeClientCredentials) {
		return nil, nil, oidc.ErrUnauthorizedClient()
	}

	tokenRequest, err := storage.ClientCredentialsTokenRequest(ctx, request.ClientID, request.Scope)
	if err != nil {
		return nil, nil, err
	}
	return tokenRequest, client, nil
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
	ctx, span := Tracer.Start(ctx, "ValidateClientCredentialsRequest")
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
	ctx, span := Tracer.Start(ctx, "AuthorizeClientCredentialsClient")
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
	ctx, span := Tracer.Start(ctx, "CreateClientCredentialsTokenResponse")
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

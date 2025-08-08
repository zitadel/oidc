package op

import (
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4/json"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"log/slog"
	"net/http"
	"strings"
)

var (
	errMissingAuthorizationHeader = errors.New("missing authorization header")
	errInvalidHeader              = errors.New("invalid header")
)

// getBearerToken extracts a bearer token from a HTTP request.
//
// For example, getBearerToken returns
// `this.is.an.access.token.value.ffx83`
// from the request below:
//
//	GET /connect/register?client_id=s6BhdRkqt3 HTTP/1.1
//	Accept: application/json
//	Host: server.example.com
//	Authorization: Bearer this.is.an.access.token.value.ffx83
func getBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("authorization")
	if auth == "" {
		return "", errMissingAuthorizationHeader
	}
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		return "", errInvalidHeader
	}
	return strings.TrimPrefix(auth, oidc.PrefixBearer), nil
}

func clientRequestError(w http.ResponseWriter, r *http.Request, lvl slog.Level, errResp *oidc.ClientInformationErrorResponse, logger *slog.Logger, status int) {
	logger.Log(r.Context(), lvl, "request error", "oidc_error", errResp)
	httphelper.MarshalJSONWithStatus(w, errResp, status)
}

func clientReadHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			clientRead(w, r, o)
		default:
			RequestError(w, r, fmt.Errorf("unsupported method: %s", r.Method), o.Logger())
		}
	}
}

// clientRead handles [client read requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Management Protocol].
//
// [client read requests]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1
// [OAuth 2.0 Dynamic Client Registration Management Protocol]: https://www.rfc-editor.org/rfc/rfc7592.html
func clientRead(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	ctx, span := tracer.Start(r.Context(), "clientRead")
	r = r.WithContext(ctx)
	defer span.End()

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req, err := ParseClientReadRequest(r, o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	registrationAccessToken, err := getBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := storage.AuthorizeClientRead(ctx, req.ClientID, registrationAccessToken); err != nil {
		if errors.Is(err, ErrInvalidClient) || errors.Is(err, ErrInvalidRegistrationAccessToken) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrClientNoPermission) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := storage.ReadClient(r.Context(), req.ClientID)
	if err != nil {
		if errors.Is(err, ErrInvalidClient) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		o.Logger().Log(r.Context(), slog.LevelError, "read client error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	httphelper.MarshalJSON(w, res)
	return
}

func ParseClientReadRequest(r *http.Request, o OpenIDProvider) (*oidc.ClientReadRequest, error) {
	ctx, span := tracer.Start(r.Context(), "ParseClientReadRequest")
	r = r.WithContext(ctx)
	defer span.End()

	req := new(oidc.ClientReadRequest)
	if err := o.Decoder().Decode(req, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse client read request").WithParent(err)
	}

	req.ClientID = chi.URLParam(r, "client_id")
	return req, nil
}

func clientRegistrationUpdateDeleteHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			clientRegistration(w, r, o)
		case http.MethodPut:
			clientUpdate(w, r, o)
		case http.MethodDelete:
			clientDelete(w, r, o)
		default:
			RequestError(w, r, fmt.Errorf("unsupported method: %s", r.Method), o.Logger())
		}
	}
}

// clientRegistration handles [client registration requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Protocol].
//
// [client registration requests]: https://www.rfc-editor.org/rfc/rfc7591#section-3.1
// [OAuth 2.0 Dynamic Client Registration Protocol]: https://www.rfc-editor.org/rfc/rfc7591
func clientRegistration(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	ctx, span := tracer.Start(r.Context(), "clientRegistration")
	r = r.WithContext(ctx)
	defer span.End()

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req, err := ParseClientRegistrationRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var initialAccessToken string
	if auth := r.Header.Get("authorization"); auth == "" {
		iat, err := getBearerToken(r)
		if err != nil && !errors.Is(err, errMissingAuthorizationHeader) {
			// allow for missing authorization header, in case the software statement is used for authentication
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		initialAccessToken = iat
	}

	if err := storage.AuthorizeClientRegistration(ctx, initialAccessToken, req); err != nil {
		if errors.Is(err, ErrInvalidInitialAccessToken) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrInvalidSoftwareStatement) {
			clientRequestError(
				w,
				r,
				slog.LevelInfo,
				&oidc.ClientInformationErrorResponse{
					Error:            oidc.ClientInformationErrorResponseErrorCodeInvalidSoftwareStatement,
					ErrorDescription: err.Error(),
				},
				o.Logger(),
				http.StatusBadRequest,
			)
			return
		}
		if errors.Is(err, ErrUnapprovedSoftwareStatement) {
			clientRequestError(
				w,
				r,
				slog.LevelInfo,
				&oidc.ClientInformationErrorResponse{
					Error:            oidc.ClientInformationErrorResponseErrorCodeUnapprovedSoftwareStatement,
					ErrorDescription: err.Error(),
				},
				o.Logger(),
				http.StatusBadRequest,
			)
			return
		}
		o.Logger().Log(r.Context(), slog.LevelError, "read client error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res, err := storage.RegisterClient(ctx, req)
	if err != nil {
		if errors.Is(err, ErrInvalidRedirectURI) {
			clientRequestError(
				w,
				r,
				slog.LevelInfo,
				&oidc.ClientInformationErrorResponse{
					Error:            oidc.ClientInformationErrorResponseErrorCodeInvalidRedirectURI,
					ErrorDescription: err.Error(),
				},
				o.Logger(),
				http.StatusBadRequest,
			)
			return
		}
		if errors.Is(err, ErrInvalidClientMetadata) {
			clientRequestError(
				w,
				r,
				slog.LevelInfo,
				&oidc.ClientInformationErrorResponse{
					Error:            oidc.ClientInformationErrorResponseErrorCodeInvalidClientMetadata,
					ErrorDescription: err.Error(),
				},
				o.Logger(),
				http.StatusBadRequest,
			)
			return
		}
		o.Logger().Log(r.Context(), slog.LevelError, "register client error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Upon a successful registration request, the authorization server
	// returns a client identifier for the client.  The server responds with
	// an HTTP 201 Created status code and a body of type "application/json"
	// containing a Client Information Response.

	httphelper.MarshalJSONWithStatus(w, res, http.StatusCreated)
	return
}

func ParseClientRegistrationRequest(r *http.Request) (*oidc.ClientRegistrationRequest, error) {
	ctx, span := tracer.Start(r.Context(), "ParseClientRegistrationRequest")
	r = r.WithContext(ctx)
	defer span.End()

	req := new(oidc.ClientRegistrationRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse client registration request").WithParent(err)
	}

	return req, nil
}

// clientUpdate handles [client update requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Management Protocol].
//
// [client update requests]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.2
// [OAuth 2.0 Dynamic Client Registration Management Protocol]: https://www.rfc-editor.org/rfc/rfc7592.html
func clientUpdate(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	ctx, span := tracer.Start(r.Context(), "clientUpdate")
	r = r.WithContext(ctx)
	defer span.End()

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req, err := ParseClientUpdateRequest(r, o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	registrationAccessToken, err := getBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := storage.AuthorizeClientUpdate(ctx, req.ClientID, registrationAccessToken); err != nil {
		if errors.Is(err, ErrInvalidClient) || errors.Is(err, ErrInvalidRegistrationAccessToken) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrClientNoPermission) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := storage.UpdateClient(ctx, req)
	if err != nil {
		if errors.Is(err, ErrInvalidClient) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrInvalidRedirectURI) {
			clientRequestError(
				w,
				r,
				slog.LevelInfo,
				&oidc.ClientInformationErrorResponse{
					Error:            oidc.ClientInformationErrorResponseErrorCodeInvalidRedirectURI,
					ErrorDescription: err.Error(),
				},
				o.Logger(),
				http.StatusBadRequest,
			)
			return
		}
		if errors.Is(err, ErrInvalidClientMetadata) {
			clientRequestError(
				w,
				r,
				slog.LevelInfo,
				&oidc.ClientInformationErrorResponse{
					Error:            oidc.ClientInformationErrorResponseErrorCodeInvalidClientMetadata,
					ErrorDescription: err.Error(),
				},
				o.Logger(),
				http.StatusBadRequest,
			)
			return
		}
		if errors.Is(err, ErrClientUpdateNotAllowed) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		o.Logger().Log(r.Context(), slog.LevelError, "update client error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	httphelper.MarshalJSON(w, res)
	return
}

func ParseClientUpdateRequest(r *http.Request, o OpenIDProvider) (*oidc.ClientUpdateRequest, error) {
	ctx, span := tracer.Start(r.Context(), "ParseClientUpdateRequest")
	r = r.WithContext(ctx)
	defer span.End()

	req := new(oidc.ClientUpdateRequest)
	if err := o.Decoder().Decode(req, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse client update request").WithParent(err)
	}

	return req, nil
}

// clientDelete handles [client delete requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Management Protocol].
//
// [client delete requests]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.3
// [OAuth 2.0 Dynamic Client Registration Management Protocol]: https://www.rfc-editor.org/rfc/rfc7592.html
func clientDelete(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	ctx, span := tracer.Start(r.Context(), "clientDelete")
	r = r.WithContext(ctx)
	defer span.End()

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req, err := ParseClientDeleteRequest(r, o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	registrationAccessToken, err := getBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := storage.AuthorizeClientDelete(ctx, req.ClientID, registrationAccessToken); err != nil {
		if errors.Is(err, ErrInvalidClient) || errors.Is(err, ErrInvalidRegistrationAccessToken) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrClientNoPermission) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := storage.DeleteClient(ctx, req.ClientID); err != nil {
		if errors.Is(err, ErrInvalidClient) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrClientDeleteNotSupported) {
			http.Error(w, err.Error(), http.StatusMethodNotAllowed)
			return
		}
		if errors.Is(err, ErrClientDeleteNotAllowed) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		o.Logger().Log(r.Context(), slog.LevelError, "delete client error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	return
}

func ParseClientDeleteRequest(r *http.Request, o OpenIDProvider) (*oidc.ClientDeleteRequest, error) {
	ctx, span := tracer.Start(r.Context(), "ParseClientDeleteRequest")
	r = r.WithContext(ctx)
	defer span.End()

	req := new(oidc.ClientDeleteRequest)
	if err := o.Decoder().Decode(req, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse client delete request").WithParent(err)
	}

	return req, nil
}

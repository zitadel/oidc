package op

import (
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v4/json"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"net/http"
)

func RegistrationHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if err := ClientRegistration(w, r, o); err != nil {
				RequestError(w, r, err, o.Logger())
			}
		case http.MethodGet:
			if err := ClientRead(w, r, o); err != nil {
				RequestError(w, r, err, o.Logger())
			}
		case http.MethodPut:
			if err := ClientUpdate(w, r, o); err != nil {
				RequestError(w, r, err, o.Logger())
			}
		case http.MethodDelete:
			if err := ClientDelete(w, r, o); err != nil {
				RequestError(w, r, err, o.Logger())
			}
		default:
			RequestError(w, r, fmt.Errorf("unsupported method: %s", r.Method), o.Logger())
		}
	}
}

// ClientRegistration handles [client registration requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Protocol].
//
// [client registration requests]: https://www.rfc-editor.org/rfc/rfc7591#section-3.1
// [OAuth 2.0 Dynamic Client Registration Protocol]: https://www.rfc-editor.org/rfc/rfc7591
func ClientRegistration(w http.ResponseWriter, r *http.Request, o OpenIDProvider) error {
	ctx, span := tracer.Start(r.Context(), "ClientRegistration")
	r = r.WithContext(ctx)
	defer span.End()

	req, err := ParseClientRegistrationRequest(r)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		return errors.New("dynamic client registration unsupported")
	}

	clientID, err := storage.RegisterClient(ctx, req)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	res, err := storage.ReadClient(ctx, clientID)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	httphelper.MarshalJSONWithStatus(w, res, http.StatusCreated)
	return nil
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

// ClientRead handles [client read requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Management Protocol].
//
// [client read requests]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1
// [OAuth 2.0 Dynamic Client Registration Management Protocol]: https://www.rfc-editor.org/rfc/rfc7592.html
func ClientRead(w http.ResponseWriter, r *http.Request, o OpenIDProvider) error {
	ctx, span := tracer.Start(r.Context(), "ClientRead")
	r = r.WithContext(ctx)
	defer span.End()

	req, err := ParseClientReadRequest(r, o)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		return errors.New("dynamic client registration unsupported")
	}

	res, err := storage.ReadClient(r.Context(), req.ClientID)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	httphelper.MarshalJSON(w, res)
	return nil
}

func ParseClientReadRequest(r *http.Request, o OpenIDProvider) (*oidc.ClientReadRequest, error) {
	ctx, span := tracer.Start(r.Context(), "ParseClientReadRequest")
	r = r.WithContext(ctx)
	defer span.End()

	req := new(oidc.ClientReadRequest)
	if err := o.Decoder().Decode(req, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse client read request").WithParent(err)
	}

	return req, nil
}

// ClientUpdate handles [client update requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Management Protocol].
//
// [client update requests]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.2
// [OAuth 2.0 Dynamic Client Registration Management Protocol]: https://www.rfc-editor.org/rfc/rfc7592.html
func ClientUpdate(w http.ResponseWriter, r *http.Request, o OpenIDProvider) error {
	ctx, span := tracer.Start(r.Context(), "ClientUpdate")
	r = r.WithContext(ctx)
	defer span.End()

	req, err := ParseClientUpdateRequest(r, o)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		return errors.New("dynamic client registration unsupported")
	}

	if err := storage.UpdateClient(ctx, req); err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	res, err := storage.ReadClient(ctx, req.ClientID)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	httphelper.MarshalJSON(w, res)
	return nil
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

// ClientDelete handles [client delete requests] as part of the
// [OAuth 2.0 Dynamic Client Registration Management Protocol].
//
// [client delete requests]: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.3
// [OAuth 2.0 Dynamic Client Registration Management Protocol]: https://www.rfc-editor.org/rfc/rfc7592.html
func ClientDelete(w http.ResponseWriter, r *http.Request, o OpenIDProvider) error {
	ctx, span := tracer.Start(r.Context(), "ClientDelete")
	r = r.WithContext(ctx)
	defer span.End()

	req, err := ParseClientDeleteRequest(r, o)
	if err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	storage, err := assertClientStorage(o.Storage())
	if err != nil {
		return errors.New("dynamic client registration unsupported")
	}

	if err := storage.DeleteClient(ctx, req.ClientID); err != nil {
		// TODO(mqf20): be able to return the proper error codes?
		return err
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
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

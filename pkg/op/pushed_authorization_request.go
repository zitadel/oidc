package op

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type PushedAuthorizationRequestConfig struct {
	Lifetime time.Duration
}

func PushedAuthorizationRequestHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := PushedAuthorizationRequest(w, r, o); err != nil {
			RequestError(w, r, err, o.Logger())
		}
	}
}

func PushedAuthorizationRequest(w http.ResponseWriter, r *http.Request, o OpenIDProvider) error {
	ctx, span := tracer.Start(r.Context(), "PAR")
	r = r.WithContext(ctx)
	defer span.End()

	req, err := parsePARRequest(r, o.Decoder())
	if err != nil {
		return err
	}

	resp, err := createPushedAuthorizationRequest(r.Context(), req, o)
	if err != nil {
		return err
	}

	httphelper.MarshalJSON(w, resp)

	return nil
}

func createPushedAuthorizationRequest(
	ctx context.Context, req *oidc.PARRequest, o OpenIDProvider,
) (*oidc.PARResponse, error) {
	_, _, err := validateAuthRequest(ctx, (*oidc.AuthRequest)(req), o)
	if err != nil {
		return nil, err
	}

	// prevent misconfigured requests.
	if req.RedirectURI != "" {
		return nil, oidc.ErrRequestNotSupported()
	}

	config := o.PushedAuthorizationRequest()

	storage, err := assertPARStorage(o.Storage())
	if err != nil {
		return nil, err
	}

	requestURI := "urn:ietf:params:oauth:request_uri:" + uuid.NewString()

	err = storage.StorePAR(
		ctx, requestURI, (*oidc.AuthRequest)(req), time.Now().Add(config.Lifetime),
	)
	if err != nil {
		return nil, fmt.Errorf("store request data: %w", err)
	}

	resp := &oidc.PARResponse{
		RequestURI: requestURI,
		ExpiresIn:  int(config.Lifetime.Seconds()),
	}

	return resp, nil
}

func parsePARRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.PARRequest, error) {
	ctx, span := tracer.Start(r.Context(), "parsePARRequest")
	r = r.WithContext(ctx)
	defer span.End()

	err := r.ParseForm()
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	authReq := new(oidc.PARRequest)

	err = decoder.Decode(authReq, r.Form)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse request").WithParent(err)
	}

	return authReq, nil
}

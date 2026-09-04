package op

import (
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ResourceRequest is an optional interface which may be implemented by the request
// types returned by [Storage], such as [AuthRequest], [RefreshTokenRequest] or the
// [TokenRequest] of the client credentials grant.
//
// It reports the resources of [RFC 8707] that were granted to the request. The op
// package uses them to check that a `resource` value sent to the token endpoint was
// covered by the original authorization request.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
type ResourceRequest interface {
	GetResource() []string
}

// CurrentResourceSetter is an optional interface which may be implemented by the
// request types returned by [Storage], analogous to the `SetCurrentScopes` method of
// [RefreshTokenRequest].
//
// When a token request narrows the granted resources with the `resource` parameter of
// [RFC 8707, section 2.2], the op package passes the requested values to the request
// before the tokens are created, so that the implementation can bind the audience of
// the issued tokens to them.
//
// [RFC 8707, section 2.2]: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
type CurrentResourceSetter interface {
	SetCurrentResources(resources []string)
}

// ValidateResourceIndicators validates the values of the `resource` parameter against
// [RFC 8707, section 2]: every value must be an absolute URI and must not include a
// fragment component. Invalid values are rejected with the `invalid_target` error code.
//
// Only the syntax is validated here. Whether a resource is acceptable for the client,
// and how it translates into the audience of the issued tokens, is up to the [Storage]
// implementation, which receives the values as part of the request.
//
// [RFC 8707, section 2]: https://www.rfc-editor.org/rfc/rfc8707#section-2
func ValidateResourceIndicators(resources []string) error {
	for _, resource := range resources {
		if strings.Contains(resource, "#") {
			return oidc.ErrInvalidTarget().
				WithDescription("The resource parameter %q must not include a fragment component.", resource)
		}
		uri, err := url.Parse(resource)
		if err != nil {
			return oidc.ErrInvalidTarget().WithParent(err).
				WithDescription("The resource parameter %q is not a valid URI.", resource)
		}
		if !uri.IsAbs() {
			return oidc.ErrInvalidTarget().
				WithDescription("The resource parameter %q must be an absolute URI.", resource)
		}
	}
	return nil
}

// ValidateTokenRequestResources validates the `resource` values of a token request
// against [RFC 8707, section 2.2].
//
// Besides the syntax checked by [ValidateResourceIndicators], every requested value
// must be one of the resources already granted to request, if it reports any through
// the optional [ResourceRequest] interface. A request for a resource that was not
// granted is rejected with `invalid_target`.
//
// If request implements the optional [CurrentResourceSetter] interface, the requested
// resources are set on it, so that the [Storage] implementation can narrow the audience
// of the issued tokens accordingly. An empty `resource` parameter leaves the granted
// resources untouched, as the RFC requires.
//
// [RFC 8707, section 2.2]: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
func ValidateTokenRequestResources(requestedResources []string, request TokenRequest) error {
	if err := ValidateResourceIndicators(requestedResources); err != nil {
		return err
	}
	if len(requestedResources) == 0 {
		return nil
	}
	if granted, ok := request.(ResourceRequest); ok {
		grantedResources := granted.GetResource()
		if len(grantedResources) > 0 {
			for _, resource := range requestedResources {
				if !slices.Contains(grantedResources, resource) {
					return oidc.ErrInvalidTarget().
						WithDescription("The resource parameter %q was not granted by the authorization request.", resource)
				}
			}
		}
	}
	if setter, ok := request.(CurrentResourceSetter); ok {
		setter.SetCurrentResources(requestedResources)
	}
	return nil
}

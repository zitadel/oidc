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
// Implementing it opts the request into the resource indicators of [RFC 8707]. It
// reports the resources that were granted to the request: for an authorization code,
// the resources of the authorization request, for a refresh token, the resources of
// the original grant, and for the client credentials grant, the resources the client
// may request. A `resource` value sent to the token endpoint must be one of them, or
// the request is rejected with `invalid_target`. In particular, if no resources were
// granted, a token request for any resource is rejected.
//
// A request that does not implement it does not use resource indicators: a `resource`
// parameter of the token request is only checked for its syntax and is otherwise
// ignored, as it was before resource indicators were supported.
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
// before the tokens are created, so that the implementation can restrict the audience
// of the issued access token to them (see [AccessTokenAudienceRequest]).
//
// It is only used on requests that also implement [ResourceRequest], so that the
// requested resources are checked against the grant first.
//
// Only the access token is narrowed. GetResource of [ResourceRequest] must keep
// reporting the full grant, as a refresh token that is issued along with the access
// token stays bound to the full original grant.
//
// [RFC 8707, section 2.2]: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
type CurrentResourceSetter interface {
	SetCurrentResources(resources []string)
}

// AccessTokenAudienceRequest is an optional interface which may be implemented by a
// [TokenRequest] to give the access token a different audience than the ID token.
//
// GetAudience of [TokenRequest] is used for the audience of both tokens. With resource
// indicators ([RFC 8707]) the access token is addressed to the requested resources,
// whereas the ID token is addressed to the client and should not carry them. When a
// request implements this interface, GetAccessTokenAudience is used for the audience
// of JWT access tokens and GetAudience remains the audience of the ID token.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
type AccessTokenAudienceRequest interface {
	GetAccessTokenAudience() []string
}

// AccessTokenAudience returns the audience of an access token issued for request:
// the result of GetAccessTokenAudience if request implements
// [AccessTokenAudienceRequest], and of GetAudience otherwise.
//
// It is used for JWT access tokens, and may be used by [Storage] implementations to
// record the audience of opaque access tokens, so that both token types agree.
func AccessTokenAudience(request TokenRequest) []string {
	if audienceRequest, ok := request.(AccessTokenAudienceRequest); ok {
		return audienceRequest.GetAccessTokenAudience()
	}
	return request.GetAudience()
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
	// The values are caller input and are not echoed in the error description,
	// whose characters are restricted by RFC 6749, section 5.2.
	for _, resource := range resources {
		if strings.Contains(resource, "#") {
			return oidc.ErrInvalidTarget().WithDescription("resource must not include a fragment component")
		}
		uri, err := url.Parse(resource)
		if err != nil {
			return oidc.ErrInvalidTarget().WithParent(err).WithDescription("resource is not a valid URI")
		}
		if !uri.IsAbs() {
			return oidc.ErrInvalidTarget().WithDescription("resource must be an absolute URI")
		}
	}
	return nil
}

// ValidateTokenRequestResources validates the `resource` values of a token request
// against [RFC 8707, section 2.2].
//
// Besides the syntax checked by [ValidateResourceIndicators], if request implements
// the optional [ResourceRequest] interface, every requested value must be one of the
// resources it reports as granted. A request for a resource that was not granted,
// including any resource when none were granted, is rejected with `invalid_target`.
//
// If the requested resources are acceptable and request implements the optional
// [CurrentResourceSetter] interface, they are set on it, so that the [Storage]
// implementation can narrow the audience of the issued access token accordingly. An
// empty `resource` parameter leaves the granted resources in effect.
//
// [RFC 8707, section 2.2]: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
func ValidateTokenRequestResources(requestedResources []string, request TokenRequest) error {
	if err := ValidateResourceIndicators(requestedResources); err != nil {
		return err
	}
	if len(requestedResources) == 0 {
		return nil
	}
	granted, ok := request.(ResourceRequest)
	if !ok {
		// The storage does not use resource indicators.
		return nil
	}
	grantedResources := granted.GetResource()
	for _, resource := range requestedResources {
		if !slices.Contains(grantedResources, resource) {
			return oidc.ErrInvalidTarget().WithDescription("resource was not granted")
		}
	}
	if setter, ok := request.(CurrentResourceSetter); ok {
		setter.SetCurrentResources(requestedResources)
	}
	return nil
}

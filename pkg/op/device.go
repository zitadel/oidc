package op

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type DeviceAuthorizationConfig struct {
	Lifetime     time.Duration
	PollInterval time.Duration

	// UserFormURL is the complete URL where the user must go to authorize the device.
	// Deprecated: use UserFormPath instead.
	UserFormURL string

	// UserFormPath is the path where the user must go to authorize the device.
	// The hostname for the URL is taken from the request by IssuerFromContext.
	UserFormPath string
	UserCode     UserCodeConfig
}

type UserCodeConfig struct {
	CharSet      string
	CharAmount   int
	DashInterval int
}

const (
	CharSetBase20 = "BCDFGHJKLMNPQRSTVWXZ"
	CharSetDigits = "0123456789"
)

var (
	UserCodeBase20 = UserCodeConfig{
		CharSet:      CharSetBase20,
		CharAmount:   8,
		DashInterval: 4,
	}
	UserCodeDigits = UserCodeConfig{
		CharSet:      CharSetDigits,
		CharAmount:   9,
		DashInterval: 3,
	}
)

func DeviceAuthorizationHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := DeviceAuthorization(w, r, o); err != nil {
			RequestError(w, r, err, nil)
		}
	}
}

func DeviceAuthorization(w http.ResponseWriter, r *http.Request, o OpenIDProvider) error {
	ctx, span := Tracer.Start(r.Context(), "DeviceAuthorization")
	r = r.WithContext(ctx)
	defer span.End()

	req, err := ParseDeviceCodeRequest(r, o)
	if err != nil {
		return err
	}
	response, err := createDeviceAuthorization(r.Context(), req, req.ClientID, o)
	if err != nil {
		return err
	}

	httphelper.MarshalJSON(w, response)
	return nil
}

func createDeviceAuthorization(ctx context.Context, req *oidc.DeviceAuthorizationRequest, clientID string, o OpenIDProvider) (*oidc.DeviceAuthorizationResponse, error) {
	ctx, span := Tracer.Start(ctx, "createDeviceAuthorization")
	defer span.End()

	storage, err := assertDeviceStorage(o.Storage())
	if err != nil {
		return nil, err
	}
	config := o.DeviceAuthorization()

	deviceCode, _ := NewDeviceCode(RecommendedDeviceCodeBytes)
	userCode, err := NewUserCode([]rune(config.UserCode.CharSet), config.UserCode.CharAmount, config.UserCode.DashInterval)
	if err != nil {
		return nil, NewStatusError(err, http.StatusInternalServerError)
	}

	expires := time.Now().Add(config.Lifetime)
	boundStorage, keyBindingIntegrated := storage.(BoundKeyDeviceAuthorizationStorage)
	if req.DPoPJKT != "" && !keyBindingIntegrated {
		// The storage has not integrated key binding on this flow, so there is
		// nowhere to persist the thumbprint. Ignore the binding entirely rather
		// than erroring, matching how the code flow treats a storage that does
		// not implement BoundKeyRequest (Key Binding 1.0, Section 2.1).
		//
		// The `bound_key` scope has to be dropped along with dpop_jkt, not just
		// the latter: DeviceAuthorizationState always implements BoundKeyRequest,
		// so a retained scope with an empty thumbprint would look like a lost
		// binding and fail closed at the token endpoint. Dropping both makes this
		// an ordinary unbound request. A key-binding RP still fails closed, since
		// it rejects an ID Token that lacks the expected `typ` and `cnf`.
		req.DPoPJKT = ""
		req.Scopes = slices.DeleteFunc(req.Scopes, func(scope string) bool {
			return scope == oidc.ScopeBoundKey
		})
	}
	if req.DPoPJKT != "" {
		err = boundStorage.StoreBoundKeyDeviceAuthorization(ctx, clientID, deviceCode, userCode, expires, req.Scopes, req.DPoPJKT)
	} else {
		err = storage.StoreDeviceAuthorization(ctx, clientID, deviceCode, userCode, expires, req.Scopes)
	}
	if err != nil {
		return nil, NewStatusError(err, http.StatusInternalServerError)
	}

	var verification *url.URL
	if config.UserFormURL != "" {
		if verification, err = url.Parse(config.UserFormURL); err != nil {
			err = oidc.ErrServerError().WithParent(err).WithDescription("invalid URL for device user form")
			return nil, NewStatusError(err, http.StatusInternalServerError)
		}
	} else {
		if verification, err = url.Parse(IssuerFromContext(ctx)); err != nil {
			err = oidc.ErrServerError().WithParent(err).WithDescription("invalid URL for issuer")
			return nil, NewStatusError(err, http.StatusInternalServerError)
		}
		verification.Path = config.UserFormPath
	}

	response := &oidc.DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: verification.String(),
		ExpiresIn:       int(config.Lifetime / time.Second),
		Interval:        int(config.PollInterval / time.Second),
	}

	verification.RawQuery = "user_code=" + userCode
	response.VerificationURIComplete = verification.String()
	return response, nil
}

func ParseDeviceCodeRequest(r *http.Request, o OpenIDProvider) (*oidc.DeviceAuthorizationRequest, error) {
	ctx, span := Tracer.Start(r.Context(), "ParseDeviceCodeRequest")
	r = r.WithContext(ctx)
	defer span.End()

	clientID, _, err := ClientIDFromRequest(r, o)
	if err != nil {
		return nil, err
	}
	client, err := o.Storage().GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}
	if !ValidateGrantType(client, oidc.GrantTypeDeviceCode) {
		return nil, oidc.ErrUnauthorizedClient().WithDescription("client missing grant type " + string(oidc.GrantTypeDeviceCode))
	}

	req := new(oidc.DeviceAuthorizationRequest)
	if err := o.Decoder().Decode(req, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse device authentication request").WithParent(err)
	}
	req.ClientID = clientID

	if err := ValidateDeviceAuthReqBoundKey(req, client); err != nil {
		return nil, err
	}

	return req, nil
}

// ValidateDeviceAuthReqBoundKey validates the pairing of the `bound_key` scope
// and the `dpop_jkt` parameter on a Device Authorization Request, as required by
// OpenID Connect Key Binding 1.0, Section 3.1.
//
// `bound_key` is stripped when the client is not allowed to use it, mirroring
// how [ValidateAuthReqScopes] gates extension scopes on the code flow. If the
// remaining scopes do not contain `bound_key`, any dpop_jkt is cleared and
// ignored without error, since dpop_jkt is also a valid [RFC 9449, Section 10]
// parameter for plain access-token DPoP binding.
//
// EXPERIMENTAL: may change until v4
//
// [RFC 9449, Section 10]: https://www.rfc-editor.org/rfc/rfc9449#section-10
func ValidateDeviceAuthReqBoundKey(req *oidc.DeviceAuthorizationRequest, client Client) error {
	if slices.Contains(req.Scopes, oidc.ScopeBoundKey) && !client.IsScopeAllowed(oidc.ScopeBoundKey) {
		req.Scopes = slices.DeleteFunc(req.Scopes, func(scope string) bool {
			return scope == oidc.ScopeBoundKey
		})
	}
	if !slices.Contains(req.Scopes, oidc.ScopeBoundKey) {
		req.DPoPJKT = ""
		return nil
	}
	if !slices.Contains(req.Scopes, oidc.ScopeOpenID) {
		return oidc.ErrInvalidRequest().WithDescription("scope openid is required for bound_key")
	}
	if req.DPoPJKT == "" {
		return oidc.ErrInvalidRequest().WithDescription("dpop_jkt is required for bound_key")
	}
	if !oidc.ValidDPoPJKT(req.DPoPJKT) {
		return oidc.ErrInvalidRequest().WithDescription("dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint")
	}
	return nil
}

// 16 bytes gives 128 bit of entropy.
// results in a 22 character base64 encoded string.
const RecommendedDeviceCodeBytes = 16

// NewDeviceCode generates a new cryptographically secure device code as a base64 encoded string.
// The length of the string is nBytes * 4 / 3.
// An error is never returned.
//
// TODO(v4): change return type to string alone.
func NewDeviceCode(nBytes int) (string, error) {
	bytes := make([]byte, nBytes)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func NewUserCode(charSet []rune, charAmount, dashInterval int) (string, error) {
	var buf strings.Builder
	if dashInterval > 0 {
		buf.Grow(charAmount + charAmount/dashInterval - 1)
	} else {
		buf.Grow(charAmount)
	}

	max := big.NewInt(int64(len(charSet)))

	for i := 0; i < charAmount; i++ {
		if dashInterval != 0 && i != 0 && i%dashInterval == 0 {
			buf.WriteByte('-')
		}

		bi, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("%w getting entropy for user code", err)
		}

		buf.WriteRune(charSet[int(bi.Int64())])
	}

	return buf.String(), nil
}

func DeviceAccessToken(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	ctx, span := Tracer.Start(r.Context(), "DeviceAccessToken")
	defer span.End()
	r = r.WithContext(ctx)

	if err := deviceAccessToken(w, r, exchanger); err != nil {
		RequestError(w, r, err, nil)
	}
}

func deviceAccessToken(w http.ResponseWriter, r *http.Request, exchanger Exchanger) error {
	// use a limited context timeout shorter as the default
	// poll interval of 5 seconds.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	r = r.WithContext(ctx)

	clientID, clientAuthenticated, err := ClientIDFromRequest(r, exchanger)
	if err != nil {
		return err
	}

	req, err := ParseDeviceAccessTokenRequest(r, exchanger)
	if err != nil {
		return err
	}
	tokenRequest, err := CheckDeviceAuthorizationState(ctx, clientID, req.DeviceCode, exchanger)
	if err != nil {
		return err
	}

	client, err := exchanger.Storage().GetClientByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if clientAuthenticated != IsConfidentialType(client) {
		return oidc.ErrInvalidClient().WithParent(ErrNoClientCredentials).
			WithDescription("confidential client requires authentication")
	}

	// OpenID Connect Key Binding 1.0, Section 3.3: the proof is bound to the
	// device code rather than an authorization code.
	confirmation, err := verifyProviderBoundKey(r.Context(), r.Header, r.Method, tokenRequest, req.DeviceCode, exchanger)
	if err != nil {
		return err
	}

	resp, err := createDeviceTokenResponse(r.Context(), tokenRequest, exchanger, client, confirmation)
	if err != nil {
		return err
	}

	httphelper.MarshalJSON(w, resp)
	return nil
}

func ParseDeviceAccessTokenRequest(r *http.Request, exchanger Exchanger) (*oidc.DeviceAccessTokenRequest, error) {
	req := new(oidc.DeviceAccessTokenRequest)
	if err := exchanger.Decoder().Decode(req, r.PostForm); err != nil {
		return nil, err
	}
	return req, nil
}

// DeviceAuthorizationState describes the current state of
// the device authorization flow.
// It implements the [IDTokenRequest] interface.
type DeviceAuthorizationState struct {
	ClientID string
	Audience []string
	Scopes   []string
	Expires  time.Time // The time after we consider the authorization request timed-out
	Done     bool      // The user authenticated and approved the authorization request
	Denied   bool      // The user authenticated and denied the authorization request

	// DPoPJKT is the dpop_jkt thumbprint committed to by the Device
	// Authorization Request, empty when the flow is not key-bound. It makes
	// DeviceAuthorizationState implement [BoundKeyRequest].
	//
	// EXPERIMENTAL: may change until v4
	DPoPJKT string

	// The following fields are populated after Done == true
	Subject  string
	AMR      []string
	AuthTime time.Time
}

// GetDPoPJKT implements [BoundKeyRequest].
//
// EXPERIMENTAL: may change until v4
func (r *DeviceAuthorizationState) GetDPoPJKT() string {
	return r.DPoPJKT
}

func (r *DeviceAuthorizationState) GetAMR() []string {
	return r.AMR
}

func (r *DeviceAuthorizationState) GetAudience() []string {
	if !slices.Contains(r.Audience, r.ClientID) {
		r.Audience = append(r.Audience, r.ClientID)
	}
	return r.Audience
}

func (r *DeviceAuthorizationState) GetAuthTime() time.Time {
	return r.AuthTime
}

func (r *DeviceAuthorizationState) GetClientID() string {
	return r.ClientID
}

func (r *DeviceAuthorizationState) GetScopes() []string {
	return r.Scopes
}

func (r *DeviceAuthorizationState) GetSubject() string {
	return r.Subject
}

func CheckDeviceAuthorizationState(ctx context.Context, clientID, deviceCode string, exchanger Exchanger) (*DeviceAuthorizationState, error) {
	ctx, span := Tracer.Start(ctx, "CheckDeviceAuthorizationState")
	defer span.End()

	storage, err := assertDeviceStorage(exchanger.Storage())
	if err != nil {
		return nil, err
	}

	state, err := storage.GetDeviceAuthorizatonState(ctx, clientID, deviceCode)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, oidc.ErrSlowDown().WithParent(err)
	}
	if err != nil {
		return nil, oidc.ErrAccessDenied().WithParent(err)
	}
	if state.Denied {
		return state, oidc.ErrAccessDenied()
	}
	if state.Done {
		return state, nil
	}
	if time.Now().After(state.Expires) {
		return state, oidc.ErrExpiredDeviceCode()
	}
	return state, oidc.ErrAuthorizationPending()
}

func CreateDeviceTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator, client Client) (*oidc.AccessTokenResponse, error) {
	return createDeviceTokenResponse(ctx, tokenRequest, creator, client, nil)
}

func createDeviceTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator, client Client, confirmation *oidc.Confirmation) (*oidc.AccessTokenResponse, error) {
	/* TODO(v4):
	Change the TokenRequest argument type to *DeviceAuthorizationState.
	Breaking change that can not be done for v3.
	*/
	ctx, span := Tracer.Start(ctx, "CreateDeviceTokenResponse")
	defer span.End()

	accessToken, refreshToken, validity, err := CreateAccessToken(ctx, tokenRequest, client.AccessTokenType(), creator, client, "")
	if err != nil {
		return nil, err
	}

	response := &oidc.AccessTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    oidc.BearerToken,
		ExpiresIn:    uint64(validity.Seconds()),
		Scope:        tokenRequest.GetScopes(),
	}

	// TODO(v4): remove type assertion
	if idTokenRequest, ok := tokenRequest.(IDTokenRequest); ok && slices.Contains(tokenRequest.GetScopes(), oidc.ScopeOpenID) {
		response.IDToken, err = createIDToken(ctx, IssuerFromContext(ctx), idTokenRequest, client.IDTokenLifetime(), accessToken, "", creator.Storage(), client, confirmation)
		if err != nil {
			return nil, err
		}
	}

	return response, nil
}

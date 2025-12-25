package op

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"time"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// BackchannelAuthenticationConfig contains configuration for CIBA (Client Initiated Backchannel Authentication)
type BackchannelAuthenticationConfig struct {
	// Lifetime is the duration for which the auth_req_id is valid
	// Default: 5 minutes
	Lifetime time.Duration

	// PollInterval is the minimum time in seconds that the client should wait between polling requests
	// Default: 5 seconds
	PollInterval time.Duration
}

// DefaultBackchannelAuthenticationConfig provides sensible defaults for CIBA configuration
var DefaultBackchannelAuthenticationConfig = BackchannelAuthenticationConfig{
	Lifetime:     5 * time.Minute,
	PollInterval: 5 * time.Second,
}

// RecommendedAuthReqIDBytes is the recommended number of bytes for auth_req_id generation (128-bit entropy)
const RecommendedAuthReqIDBytes = 16

// NewAuthReqID generates a cryptographically secure auth_req_id with the specified number of bytes
func NewAuthReqID(nBytes int) (string, error) {
	bytes := make([]byte, nBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// BackchannelAuthenticationState represents the current state of a CIBA authentication request
// Implements the IDTokenRequest interface
type BackchannelAuthenticationState struct {
	ClientID       string
	Audience       []string
	Scopes         []string
	Expires        time.Time // The time after which the auth_req_id is considered expired
	Done           bool      // The user authenticated and approved the request
	Denied         bool      // The user authenticated but denied the request
	LoginHint      string    // The login hint provided by the client
	BindingMessage string    // The binding message to display to the user

	// The following fields are populated after Done == true
	Subject  string
	AMR      []string
	AuthTime time.Time
}

// GetAMR implements the IDTokenRequest interface
func (b *BackchannelAuthenticationState) GetAMR() []string {
	return b.AMR
}

// GetAudience implements the IDTokenRequest interface
func (b *BackchannelAuthenticationState) GetAudience() []string {
	if !slices.Contains(b.Audience, b.ClientID) {
		b.Audience = append(b.Audience, b.ClientID)
	}
	return b.Audience
}

// GetAuthTime implements the IDTokenRequest interface
func (b *BackchannelAuthenticationState) GetAuthTime() time.Time {
	return b.AuthTime
}

// GetClientID implements the IDTokenRequest interface
func (b *BackchannelAuthenticationState) GetClientID() string {
	return b.ClientID
}

// GetScopes implements the IDTokenRequest interface
func (b *BackchannelAuthenticationState) GetScopes() []string {
	return b.Scopes
}

// GetSubject implements the IDTokenRequest interface
func (b *BackchannelAuthenticationState) GetSubject() string {
	return b.Subject
}

// BackchannelAuthenticationHandler creates an HTTP handler for the backchannel authentication endpoint
func BackchannelAuthenticationHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := BackchannelAuthentication(w, r, o); err != nil {
			RequestError(w, r, err, o.Logger())
		}
	}
}

// BackchannelAuthentication processes a backchannel authentication request
func BackchannelAuthentication(w http.ResponseWriter, r *http.Request, o OpenIDProvider) error {
	ctx, span := tracer.Start(r.Context(), "BackchannelAuthentication")
	r = r.WithContext(ctx)
	defer span.End()

	// Authenticate the client and get client ID
	clientID, authenticated, err := ClientIDFromRequest(r, o)
	if err != nil {
		return err
	}

	// Get client configuration
	client, err := o.Storage().GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return err
	}

	// Verify confidential clients are authenticated (CIBA spec requirement Section 7.1)
	if IsConfidentialType(client) && !authenticated {
		return oidc.ErrInvalidClient().WithDescription("confidential client must authenticate")
	}

	// Validate client supports CIBA grant type
	if !ValidateGrantType(client, oidc.GrantTypeCIBA) {
		return oidc.ErrUnauthorizedClient().WithDescription("client missing grant type " + string(oidc.GrantTypeCIBA))
	}

	// Parse and validate the request
	req, err := ParseBackchannelAuthenticationRequest(r, o, clientID)
	if err != nil {
		return err
	}

	// Create the authentication request and response
	response, err := createBackchannelAuthentication(r.Context(), req, o)
	if err != nil {
		return err
	}

	httphelper.MarshalJSON(w, response)
	return nil
}

// ParseBackchannelAuthenticationRequest parses and validates a backchannel authentication request
func ParseBackchannelAuthenticationRequest(r *http.Request, o OpenIDProvider, clientID string) (*oidc.BackchannelAuthenticationRequest, error) {
	ctx, span := tracer.Start(r.Context(), "ParseBackchannelAuthenticationRequest")
	r = r.WithContext(ctx)
	defer span.End()

	req := new(oidc.BackchannelAuthenticationRequest)
	if err := o.Decoder().Decode(req, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse backchannel authentication request").WithParent(err)
	}
	req.ClientID = clientID

	// Validate that login_hint is provided (required for v1 implementation)
	if req.LoginHint == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("login_hint is required")
	}

	// Validate binding_message length (max 20 characters per CIBA spec Section 7.1)
	if len(req.BindingMessage) > 20 {
		return nil, oidc.ErrInvalidRequest().WithDescription("binding_message must not exceed 20 characters")
	}

	return req, nil
}

// createBackchannelAuthentication creates a new backchannel authentication request
func createBackchannelAuthentication(ctx context.Context, req *oidc.BackchannelAuthenticationRequest, o OpenIDProvider) (*oidc.BackchannelAuthenticationResponse, error) {
	ctx, span := tracer.Start(ctx, "createBackchannelAuthentication")
	defer span.End()

	// Ensure storage implements BackchannelAuthenticationStorage
	storage, err := assertBackchannelStorage(o.Storage())
	if err != nil {
		return nil, err
	}

	config := o.BackchannelAuthentication()

	// Generate cryptographically secure auth_req_id
	authReqID, err := NewAuthReqID(RecommendedAuthReqIDBytes)
	if err != nil {
		return nil, NewStatusError(err, http.StatusInternalServerError)
	}

	// Determine expiry time
	expires := time.Now().Add(config.Lifetime)
	if req.RequestedExpiry > 0 {
		requestedExpires := time.Now().Add(time.Duration(req.RequestedExpiry) * time.Second)
		// Use the requested expiry if it's earlier than the default
		if requestedExpires.Before(expires) {
			expires = requestedExpires
		}
	}

	// Store the authentication request
	// Note: The storage implementation should trigger notification to the user's device here
	err = storage.StoreBackchannelAuthentication(ctx, req.ClientID, authReqID, expires, req.Scopes, req.LoginHint, req.BindingMessage)
	if err != nil {
		return nil, NewStatusError(err, http.StatusInternalServerError)
	}

	// Return the response with auth_req_id
	response := &oidc.BackchannelAuthenticationResponse{
		AuthReqID: authReqID,
		ExpiresIn: int(config.Lifetime / time.Second),
		Interval:  int(config.PollInterval / time.Second),
	}

	return response, nil
}

// BackchannelAccessToken handles token requests for the CIBA grant type
func BackchannelAccessToken(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	ctx, span := tracer.Start(r.Context(), "BackchannelAccessToken")
	defer span.End()
	r = r.WithContext(ctx)

	if err := backchannelAccessToken(w, r, exchanger); err != nil {
		RequestError(w, r, err, exchanger.Logger())
	}
}

func backchannelAccessToken(w http.ResponseWriter, r *http.Request, exchanger Exchanger) error {
	// Use a shorter timeout than the poll interval to trigger slow_down if needed
	// Similar to device flow pattern
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	r = r.WithContext(ctx)

	// Authenticate the client
	clientID, clientAuthenticated, err := ClientIDFromRequest(r, exchanger)
	if err != nil {
		return err
	}

	// Parse the token request
	req := new(oidc.BackchannelTokenRequest)
	if err := exchanger.Decoder().Decode(req, r.PostForm); err != nil {
		return oidc.ErrInvalidRequest().WithDescription("cannot parse backchannel token request").WithParent(err)
	}

	// Check the current state of the authentication
	tokenRequest, err := CheckBackchannelAuthenticationState(ctx, clientID, req.AuthReqID, exchanger)
	if err != nil {
		return err
	}

	// Get client configuration
	client, err := exchanger.Storage().GetClientByClientID(ctx, clientID)
	if err != nil {
		return err
	}

	// Verify confidential clients are authenticated
	if clientAuthenticated != IsConfidentialType(client) {
		return oidc.ErrInvalidClient().WithParent(ErrNoClientCredentials).
			WithDescription("confidential client requires authentication")
	}

	// Create the token response
	resp, err := CreateBackchannelTokenResponse(r.Context(), tokenRequest, exchanger, client)
	if err != nil {
		return err
	}

	httphelper.MarshalJSON(w, resp)
	return nil
}

// CheckBackchannelAuthenticationState checks the current state of a CIBA authentication request
// and returns the appropriate error based on the state
func CheckBackchannelAuthenticationState(ctx context.Context, clientID, authReqID string, exchanger Exchanger) (*BackchannelAuthenticationState, error) {
	ctx, span := tracer.Start(ctx, "CheckBackchannelAuthenticationState")
	defer span.End()

	storage, err := assertBackchannelStorage(exchanger.Storage())
	if err != nil {
		return nil, err
	}

	state, err := storage.GetBackchannelAuthenticationState(ctx, clientID, authReqID)
	if errors.Is(err, context.DeadlineExceeded) {
		// Client is polling too fast, return slow_down
		return nil, oidc.ErrSlowDown().WithParent(err)
	}
	if err != nil {
		// auth_req_id not found or other error
		return nil, oidc.ErrAccessDenied().WithParent(err)
	}

	// Check if the user denied the request
	if state.Denied {
		return state, oidc.ErrAccessDenied().WithDescription("user denied the authentication request")
	}

	// Check if the request has expired
	if time.Now().After(state.Expires) {
		return state, oidc.ErrExpiredToken().WithDescription("the auth_req_id has expired")
	}

	// Check if authentication is complete
	if state.Done {
		return state, nil
	}

	// Still waiting for user to authenticate
	return state, oidc.ErrAuthorizationPending()
}

// CreateBackchannelTokenResponse creates the token response for a completed CIBA authentication
// Reuses the device flow token creation logic as the structure is identical
func CreateBackchannelTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator, client Client) (*oidc.AccessTokenResponse, error) {
	ctx, span := tracer.Start(ctx, "CreateBackchannelTokenResponse")
	defer span.End()

	// The token creation logic is identical to device flow
	return CreateDeviceTokenResponse(ctx, tokenRequest, creator, client)
}

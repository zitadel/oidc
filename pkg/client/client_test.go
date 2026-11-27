package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestDiscover(t *testing.T) {
	type wantFields struct {
		UILocalesSupported bool
	}

	type args struct {
		issuer       string
		wellKnownUrl []string
	}
	tests := []struct {
		name       string
		args       args
		wantFields *wantFields
		wantErr    error
	}{
		{
			name: "spotify", // https://github.com/zitadel/oidc/issues/406
			args: args{
				issuer: "https://accounts.spotify.com",
			},
			wantFields: &wantFields{
				UILocalesSupported: true,
			},
			wantErr: nil,
		},
		{
			name: "discovery failed",
			args: args{
				issuer: "https://example.com",
			},
			wantErr: oidc.ErrDiscoveryFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Discover(context.Background(), tt.args.issuer, http.DefaultClient, tt.args.wellKnownUrl...)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantFields == nil {
				return
			}
			assert.Equal(t, tt.args.issuer, got.Issuer)
			if tt.wantFields.UILocalesSupported {
				assert.NotEmpty(t, got.UILocalesSupported)
			}
		})
	}
}

func TestDiscover_ContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{name: "application/json", contentType: "application/json"},
		{name: "application/json with charset", contentType: "application/json; charset=utf-8"},
		{name: "mixed case", contentType: "Application/JSON"},
		{name: "missing", contentType: "", wantErr: true},
		{name: "text/plain", contentType: "text/plain; charset=utf-8", wantErr: true},
		{name: "text/html", contentType: "text/html", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var issuer string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Setting the header to nil prevents net/http from sniffing a content type.
				w.Header()["Content-Type"] = nil
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				_, _ = w.Write([]byte(`{"issuer":"` + issuer + `"}`))
			}))
			defer server.Close()
			issuer = server.URL

			got, err := Discover(context.Background(), issuer, server.Client())
			if tt.wantErr {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				require.ErrorIs(t, err, httphelper.ErrInvalidContentType)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, issuer, got.Issuer)
		})
	}
}

type mockRevokeCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockRevokeCaller) GetRevokeEndpoint() string {
	return m.endpoint
}

func (m *mockRevokeCaller) HttpClient() *http.Client {
	return m.httpClient
}

type mockEndSessionCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockEndSessionCaller) GetEndSessionEndpoint() string {
	return m.endpoint
}

func (m *mockEndSessionCaller) HttpClient() *http.Client {
	return m.httpClient
}

type mockDeviceAuthorizationCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockDeviceAuthorizationCaller) GetDeviceAuthorizationEndpoint() string {
	return m.endpoint
}

func (m *mockDeviceAuthorizationCaller) HttpClient() *http.Client {
	return m.httpClient
}

func TestCallDeviceAuthorizationEndpointOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    []DeviceAuthorizationOption
		wantJKT string
	}{
		{name: "without options"},
		{name: "with dpop_jkt", opts: []DeviceAuthorizationOption{WithDPoPJKT("thumbprint")}, wantJKT: "thumbprint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				form     url.Values
				parseErr error
			)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				parseErr = r.ParseForm()
				if parseErr != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				form = r.PostForm
				_, _ = w.Write([]byte("{}"))
			}))
			defer server.Close()

			caller := &mockDeviceAuthorizationCaller{endpoint: server.URL, httpClient: server.Client()}
			request := &oidc.ClientCredentialsRequest{ClientID: "client", Scope: []string{"openid"}}
			_, err := CallDeviceAuthorizationEndpoint(context.Background(), request, caller, nil, tt.opts...)
			require.NoError(t, err)
			require.NoError(t, parseErr)
			assert.Equal(t, "client", form.Get("client_id"))
			assert.Equal(t, "openid", form.Get("scope"))
			assert.Equal(t, tt.wantJKT, form.Get("dpop_jkt"))
		})
	}
}

func TestCallTokenEndpoint_PreservesExtraFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "new-access-token",
			"token_type": "Bearer",
			"refresh_token": "new-refresh-token",
			"expires_in": 3600,
			"id_token": "new-id-token",
			"refresh_expires_in": 7200,
			"session_state": "session-1"
		}`))
	}))
	defer server.Close()

	caller := &mockTokenCaller{endpoint: server.URL, httpClient: server.Client()}
	token, err := CallTokenEndpoint(context.Background(), &oidc.RefreshTokenRequest{RefreshToken: "old-refresh-token"}, caller)
	require.NoError(t, err)

	assert.Equal(t, "new-access-token", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "new-refresh-token", token.RefreshToken)
	assert.Equal(t, "new-id-token", token.Extra("id_token"))
	assert.Equal(t, float64(7200), token.Extra("refresh_expires_in"))
	assert.Equal(t, "session-1", token.Extra("session_state"))
}

func TestCallTokenEndpoint_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`["not", "an", "object"]`))
	}))
	defer server.Close()

	caller := &mockTokenCaller{endpoint: server.URL, httpClient: server.Client()}
	_, err := CallTokenEndpoint(context.Background(), &oidc.RefreshTokenRequest{RefreshToken: "old-refresh-token"}, caller)
	require.Error(t, err)
}

type mockTokenCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockTokenCaller) TokenEndpoint() string {
	return m.endpoint
}

func (m *mockTokenCaller) HttpClient() *http.Client {
	return m.httpClient
}

func TestCallRevokeEndpoint_CheckRedirectUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	customErr := errors.New("custom redirect error")
	customRedirect := func(_ *http.Request, _ []*http.Request) error {
		return customErr
	}

	tests := []struct {
		name          string
		initialClient *http.Client
		checkFn       func(t *testing.T, client *http.Client)
	}{
		{
			name:          "nil CheckRedirect",
			initialClient: &http.Client{CheckRedirect: nil},
			checkFn: func(t *testing.T, client *http.Client) {
				assert.Nil(t, client.CheckRedirect)
			},
		},
		{
			name:          "custom CheckRedirect",
			initialClient: &http.Client{CheckRedirect: customRedirect},
			checkFn: func(t *testing.T, client *http.Client) {
				require.NotNil(t, client.CheckRedirect)
				assert.Equal(t, reflect.ValueOf(customRedirect).Pointer(), reflect.ValueOf(client.CheckRedirect).Pointer())
				assert.ErrorIs(t, client.CheckRedirect(nil, nil), customErr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := &mockRevokeCaller{
				endpoint:   server.URL,
				httpClient: tt.initialClient,
			}
			req := &RevokeRequest{
				Token: "test-token",
			}
			err := CallRevokeEndpoint(context.Background(), req, nil, caller)
			require.NoError(t, err)
			tt.checkFn(t, tt.initialClient)
		})
	}
}

func TestCallEndSessionEndpoint_CheckRedirectUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/callback", http.StatusFound)
	}))
	defer server.Close()

	customErr := errors.New("custom redirect error")
	customRedirect := func(_ *http.Request, _ []*http.Request) error {
		return customErr
	}

	tests := []struct {
		name          string
		initialClient *http.Client
		checkFn       func(t *testing.T, client *http.Client)
	}{
		{
			name:          "nil CheckRedirect",
			initialClient: &http.Client{CheckRedirect: nil},
			checkFn: func(t *testing.T, client *http.Client) {
				assert.Nil(t, client.CheckRedirect)
			},
		},
		{
			name:          "custom CheckRedirect",
			initialClient: &http.Client{CheckRedirect: customRedirect},
			checkFn: func(t *testing.T, client *http.Client) {
				require.NotNil(t, client.CheckRedirect)
				assert.Equal(t, reflect.ValueOf(customRedirect).Pointer(), reflect.ValueOf(client.CheckRedirect).Pointer())
				assert.ErrorIs(t, client.CheckRedirect(nil, nil), customErr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := &mockEndSessionCaller{
				endpoint:   server.URL,
				httpClient: tt.initialClient,
			}
			req := &oidc.EndSessionRequest{
				IdTokenHint: "test-id-token",
			}
			loc, err := CallEndSessionEndpoint(context.Background(), req, nil, caller)
			require.NoError(t, err)
			require.NotNil(t, loc)
			assert.Equal(t, "https://example.com/callback", loc.String())
			tt.checkFn(t, tt.initialClient)
		})
	}
}

func TestSignedJWTProfileAssertion_JWTID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)

	jti := func() string {
		assertion, err := SignedJWTProfileAssertion("client", []string{"https://issuer.example"}, time.Minute, signer)
		require.NoError(t, err)
		var claims oidc.JWTTokenRequest
		_, err = oidc.ParseToken(assertion, &claims)
		require.NoError(t, err)
		return claims.JWTID
	}
	// OpenID Connect Core 1.0, section 9 (private_key_jwt): jti is required
	// and must be unique, so the authorization server can refuse a replay.
	first, second := jti(), jti()
	assert.NotEmpty(t, first)
	assert.NotEqual(t, first, second)
}

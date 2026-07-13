package op_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v4/pkg/oidc"
	"github.com/zitadel/oidc/v4/pkg/op"
)

func TestLegacyServer_CodeExchange_ClientOwnership(t *testing.T) {
	server := op.RegisterLegacyServer(
		op.NewLegacyServer(testProvider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(testProvider),
	)

	storage := testProvider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)

	// Client A ("web") — the legitimate owner of the authorization code.
	clientA, err := storage.GetClientByClientID(ctx, "web")
	require.NoError(t, err)

	authReq, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     clientA.GetID(),
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: oidc.ResponseTypeCode,
	}, "user-1")
	require.NoError(t, err)
	storage.AuthRequestDone(authReq.GetID())
	storage.SaveAuthCode(ctx, authReq.GetID(), "test-code-x")

	// Client B ("api") — attempts to exchange a code it does not own.
	clientB, err := storage.GetClientByClientID(ctx, "api")
	require.NoError(t, err)

	form := url.Values{
		"grant_type":   {string(oidc.GrantTypeCode)},
		"code":         {"test-code-x"},
		"redirect_uri": {"https://example.com"},
	}

	u, err := url.Parse(testProvider.TokenEndpoint().Absolute(testIssuer))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientB.GetID(), "secret")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	resp := rec.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var errResp oidc.Error
	err = json.Unmarshal(body, &errResp)
	require.NoError(t, err)

	require.Equal(t, oidc.ErrInvalidGrant().Error(), errResp.Error())
	require.Empty(t, errResp.Description,
		"client mismatch must not include a description — it would leak information")
}

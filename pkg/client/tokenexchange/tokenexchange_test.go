package tokenexchange

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestExchangeToken_OmitsUnsetParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		for _, p := range []string{"actor_token", "actor_token_type", "resource", "audience", "scope", "requested_token_type"} {
			assert.NotContains(t, r.PostForm, p)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"a","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`))
	}))
	defer server.Close()

	te, err := NewTokenExchanger(context.Background(), "https://issuer.example", WithStaticTokenEndpoint("https://issuer.example", server.URL))
	require.NoError(t, err)
	_, err = ExchangeToken(context.Background(), te, "subject", oidc.AccessTokenType, "", "", nil, nil, nil, "")
	require.NoError(t, err)
}

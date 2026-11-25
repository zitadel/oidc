package op

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v4/pkg/oidc"
)

func TestClientAuthError(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		wantType        string
		wantDescription string
		// wantStatus is the status of a StatusError in the result, if any.
		wantStatus int
	}{
		{
			name:     "context deadline",
			err:      fmt.Errorf("lookup: %w", context.DeadlineExceeded),
			wantType: string(oidc.ServerError),
		},
		{
			name:     "context canceled",
			err:      fmt.Errorf("lookup: %w", context.Canceled),
			wantType: string(oidc.ServerError),
		},
		{
			name:            "invalid_client keeps the storage description",
			err:             oidc.ErrInvalidClient().WithDescription("%s", "client 100% disabled"),
			wantType:        string(oidc.InvalidClient),
			wantDescription: "client 100% disabled",
		},
		{
			name:            "invalid_client in a status error keeps the status",
			err:             NewStatusError(oidc.ErrInvalidClient().WithDescription("client disabled"), http.StatusForbidden),
			wantType:        string(oidc.InvalidClient),
			wantDescription: "client disabled",
			wantStatus:      http.StatusForbidden,
		},
		{
			name:            "invalid_client without a description keeps the base description",
			err:             oidc.ErrInvalidClient(),
			wantType:        string(oidc.InvalidClient),
			wantDescription: "base",
		},
		{
			name:            "other type keeps the base description",
			err:             oidc.ErrInvalidScope().WithDescription("bad scope"),
			wantType:        string(oidc.InvalidClient),
			wantDescription: "base",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientAuthError(oidc.ErrInvalidClient().WithDescription("base"), tt.err)
			require.ErrorIs(t, got, tt.err)
			assert.Equal(t, tt.wantType, string(got.ErrorType))
			assert.Equal(t, tt.wantDescription, got.Description)
			if tt.wantStatus != 0 {
				assert.Equal(t, tt.wantStatus, AsStatusError(got, http.StatusUnauthorized).statusCode)
			}
		})
	}
}

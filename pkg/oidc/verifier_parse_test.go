package oidc_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestParseToken(t *testing.T) {
	token, wantClaims := tu.ValidIDToken()
	wantClaims.SignatureAlg = "" // unset, because is not part of the JSON payload

	wantPayload, err := json.Marshal(wantClaims)
	require.NoError(t, err)

	tests := []struct {
		name        string
		tokenString string
		wantErr     bool
	}{
		{
			name:        "split error",
			tokenString: "nope",
			wantErr:     true,
		},
		{
			name:        "base64 error",
			tokenString: "foo.~.bar",
			wantErr:     true,
		},
		{
			name:        "success",
			tokenString: token,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClaims := new(oidc.IDTokenClaims)
			gotPayload, err := oidc.ParseToken(tt.tokenString, gotClaims)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, wantClaims, gotClaims)
			assert.JSONEq(t, string(wantPayload), string(gotPayload))
		})
	}
}

func TestCheckSignature(t *testing.T) {
	errCtx, cancel := context.WithCancel(context.Background())
	cancel()

	token, _ := tu.ValidIDToken()
	payload, err := oidc.ParseToken(token, &oidc.IDTokenClaims{})
	require.NoError(t, err)

	type args struct {
		ctx              context.Context
		token            string
		payload          []byte
		supportedSigAlgs []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "parse error",
			args: args{
				ctx:     context.Background(),
				token:   "~",
				payload: payload,
			},
			wantErr: oidc.ErrParse,
		},
		{
			name: "default sigAlg",
			args: args{
				ctx:     context.Background(),
				token:   token,
				payload: payload,
			},
		},
		{
			name: "unsupported sigAlg",
			args: args{
				ctx:              context.Background(),
				token:            token,
				payload:          payload,
				supportedSigAlgs: []string{"foo", "bar"},
			},
			wantErr: oidc.ErrSignatureUnsupportedAlg,
		},
		{
			name: "verify error",
			args: args{
				ctx:     errCtx,
				token:   token,
				payload: payload,
			},
			wantErr: oidc.ErrSignatureInvalid,
		},
		{
			name: "inequal payloads",
			args: args{
				ctx:     context.Background(),
				token:   token,
				payload: []byte{0, 1, 2},
			},
			wantErr: oidc.ErrSignatureInvalidPayload,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := new(oidc.TokenClaims)
			err := oidc.CheckSignature(tt.args.ctx, tt.args.token, tt.args.payload, claims, tt.args.supportedSigAlgs, tu.KeySet{})
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

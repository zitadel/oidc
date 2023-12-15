package op_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	mr "math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func Test_deviceAuthorizationHandler(t *testing.T) {
	type conf struct {
		UserFormURL  string
		UserFormPath string
	}
	tests := []struct {
		name string
		conf conf
	}{
		{
			name: "UserFormURL",
			conf: conf{
				UserFormURL: "https://localhost:9998/device",
			},
		},
		{
			name: "UserFormPath",
			conf: conf{
				UserFormPath: "/device",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := gu.PtrCopy(testConfig)
			conf.DeviceAuthorization.UserFormURL = tt.conf.UserFormURL
			conf.DeviceAuthorization.UserFormPath = tt.conf.UserFormPath
			provider := newTestProvider(conf)

			req := &oidc.DeviceAuthorizationRequest{
				Scopes:   []string{"foo", "bar"},
				ClientID: "device",
			}
			values := make(url.Values)
			testProvider.Encoder().Encode(req, values)
			body := strings.NewReader(values.Encode())

			r := httptest.NewRequest(http.MethodPost, "/", body)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r = r.WithContext(op.ContextWithIssuer(r.Context(), testIssuer))

			w := httptest.NewRecorder()

			runWithRandReader(mr.New(mr.NewSource(1)), func() {
				op.DeviceAuthorizationHandler(provider)(w, r)
			})

			result := w.Result()

			assert.Less(t, result.StatusCode, 300)

			got, _ := io.ReadAll(result.Body)
			assert.JSONEq(t, `{"device_code":"Uv38ByGCZU8WP18PmmIdcg", "expires_in":300, "interval":5, "user_code":"JKRV-FRGK", "verification_uri":"https://localhost:9998/device", "verification_uri_complete":"https://localhost:9998/device?user_code=JKRV-FRGK"}`, string(got))
		})
	}
}

func TestParseDeviceCodeRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *oidc.DeviceAuthorizationRequest
		wantErr bool
	}{
		{
			name:    "empty request",
			wantErr: true,
		},
		{
			name: "missing grant type",
			req: &oidc.DeviceAuthorizationRequest{
				Scopes:   oidc.SpaceDelimitedArray{"foo", "bar"},
				ClientID: "web",
			},
			wantErr: true,
		},
		{
			name: "client not found",
			req: &oidc.DeviceAuthorizationRequest{
				Scopes:   oidc.SpaceDelimitedArray{"foo", "bar"},
				ClientID: "foobar",
			},
			wantErr: true,
		},
		{
			name: "success",
			req: &oidc.DeviceAuthorizationRequest{
				Scopes:   oidc.SpaceDelimitedArray{"foo", "bar"},
				ClientID: "device",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.req != nil {
				values := make(url.Values)
				testProvider.Encoder().Encode(tt.req, values)
				body = strings.NewReader(values.Encode())
			}

			r := httptest.NewRequest(http.MethodPost, "/", body)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			got, err := op.ParseDeviceCodeRequest(r, testProvider)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			assert.Equal(t, tt.req, got)
		})
	}
}

func runWithRandReader(r io.Reader, f func()) {
	originalReader := rand.Reader
	rand.Reader = r
	defer func() {
		rand.Reader = originalReader
	}()

	f()
}

func TestNewDeviceCode(t *testing.T) {
	t.Run("reader error", func(t *testing.T) {
		runWithRandReader(errReader{}, func() {
			_, err := op.NewDeviceCode(16)
			require.Error(t, err)
		})
	})

	t.Run("different lengths, rand reader", func(t *testing.T) {
		for i := 1; i <= 32; i++ {
			got, err := op.NewDeviceCode(i)
			require.NoError(t, err)
			assert.Len(t, got, base64.RawURLEncoding.EncodedLen(i))
		}
	})

}

func TestNewUserCode(t *testing.T) {
	type args struct {
		charset      []rune
		charAmount   int
		dashInterval int
	}
	tests := []struct {
		name    string
		args    args
		reader  io.Reader
		want    string
		wantErr bool
	}{
		{
			name: "reader error",
			args: args{
				charset:      []rune(op.CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader:  errReader{},
			wantErr: true,
		},
		{
			name: "base20",
			args: args{
				charset:      []rune(op.CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader: mr.New(mr.NewSource(1)),
			want:   "XKCD-HTTD",
		},
		{
			name: "digits",
			args: args{
				charset:      []rune(op.CharSetDigits),
				charAmount:   9,
				dashInterval: 3,
			},
			reader: mr.New(mr.NewSource(1)),
			want:   "271-256-225",
		},
		{
			name: "no dashes",
			args: args{
				charset:    []rune(op.CharSetDigits),
				charAmount: 9,
			},
			reader: mr.New(mr.NewSource(1)),
			want:   "271256225",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runWithRandReader(tt.reader, func() {
				got, err := op.NewUserCode(tt.args.charset, tt.args.charAmount, tt.args.dashInterval)
				if tt.wantErr {
					require.ErrorIs(t, err, io.ErrNoProgress)
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, tt.want, got)
			})

		})
	}

	t.Run("crypto/rand", func(t *testing.T) {
		const testN = 100000

		for _, c := range []op.UserCodeConfig{op.UserCodeBase20, op.UserCodeDigits} {
			t.Run(c.CharSet, func(t *testing.T) {
				results := make(map[string]int)

				for i := 0; i < testN; i++ {
					code, err := op.NewUserCode([]rune(c.CharSet), c.CharAmount, c.DashInterval)
					require.NoError(t, err)
					results[code]++
				}

				t.Log(results)

				var duplicates int
				for code, count := range results {
					assert.Less(t, count, 3, code)
					if count == 2 {
						duplicates++
					}
				}

			})
		}
	})
}

func BenchmarkNewUserCode(b *testing.B) {
	type args struct {
		charset      []rune
		charAmount   int
		dashInterval int
	}
	tests := []struct {
		name   string
		args   args
		reader io.Reader
	}{
		{
			name: "math rand, base20",
			args: args{
				charset:      []rune(op.CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader: mr.New(mr.NewSource(1)),
		},
		{
			name: "math rand, digits",
			args: args{
				charset:      []rune(op.CharSetDigits),
				charAmount:   9,
				dashInterval: 3,
			},
			reader: mr.New(mr.NewSource(1)),
		},
		{
			name: "crypto rand, base20",
			args: args{
				charset:      []rune(op.CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader: rand.Reader,
		},
		{
			name: "crypto rand, digits",
			args: args{
				charset:      []rune(op.CharSetDigits),
				charAmount:   9,
				dashInterval: 3,
			},
			reader: rand.Reader,
		},
	}
	for _, tt := range tests {
		runWithRandReader(tt.reader, func() {
			b.Run(tt.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := op.NewUserCode(tt.args.charset, tt.args.charAmount, tt.args.dashInterval)
					require.NoError(b, err)
				}
			})

		})
	}
}

func TestDeviceAccessToken(t *testing.T) {
	storage := testProvider.Storage().(*storage.Storage)
	storage.StoreDeviceAuthorization(context.Background(), "native", "qwerty", "yuiop", time.Now().Add(time.Minute), []string{"foo"})
	storage.CompleteDeviceAuthorization(context.Background(), "yuiop", "tim")

	values := make(url.Values)
	values.Set("client_id", "native")
	values.Set("grant_type", string(oidc.GrantTypeDeviceCode))
	values.Set("device_code", "qwerty")

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	op.DeviceAccessToken(w, r, testProvider)

	result := w.Result()
	got, _ := io.ReadAll(result.Body)
	t.Log(string(got))
	assert.Less(t, result.StatusCode, 300)
	assert.NotEmpty(t, string(got))
}

func TestCheckDeviceAuthorizationState(t *testing.T) {
	now := time.Now()

	storage := testProvider.Storage().(*storage.Storage)
	storage.StoreDeviceAuthorization(context.Background(), "native", "pending", "pending", now.Add(time.Minute), []string{"foo"})
	storage.StoreDeviceAuthorization(context.Background(), "native", "denied", "denied", now.Add(time.Minute), []string{"foo"})
	storage.StoreDeviceAuthorization(context.Background(), "native", "completed", "completed", now.Add(time.Minute), []string{"foo"})
	storage.StoreDeviceAuthorization(context.Background(), "native", "expired", "expired", now.Add(-time.Minute), []string{"foo"})

	storage.DenyDeviceAuthorization(context.Background(), "denied")
	storage.CompleteDeviceAuthorization(context.Background(), "completed", "tim")

	exceededCtx, cancel := context.WithTimeout(context.Background(), -time.Second)
	defer cancel()

	type args struct {
		ctx        context.Context
		clientID   string
		deviceCode string
	}
	tests := []struct {
		name    string
		args    args
		want    *op.DeviceAuthorizationState
		wantErr error
	}{
		{
			name: "pending",
			args: args{
				ctx:        context.Background(),
				clientID:   "native",
				deviceCode: "pending",
			},
			want: &op.DeviceAuthorizationState{
				ClientID: "native",
				Scopes:   []string{"foo"},
				Expires:  now.Add(time.Minute),
			},
			wantErr: oidc.ErrAuthorizationPending(),
		},
		{
			name: "slow down",
			args: args{
				ctx:        exceededCtx,
				clientID:   "native",
				deviceCode: "ok",
			},
			wantErr: oidc.ErrSlowDown(),
		},
		{
			name: "wrong client",
			args: args{
				ctx:        context.Background(),
				clientID:   "foo",
				deviceCode: "ok",
			},
			wantErr: oidc.ErrAccessDenied(),
		},
		{
			name: "denied",
			args: args{
				ctx:        context.Background(),
				clientID:   "native",
				deviceCode: "denied",
			},
			want: &op.DeviceAuthorizationState{
				ClientID: "native",
				Scopes:   []string{"foo"},
				Expires:  now.Add(time.Minute),
				Denied:   true,
			},
			wantErr: oidc.ErrAccessDenied(),
		},
		{
			name: "completed",
			args: args{
				ctx:        context.Background(),
				clientID:   "native",
				deviceCode: "completed",
			},
			want: &op.DeviceAuthorizationState{
				ClientID: "native",
				Scopes:   []string{"foo"},
				Expires:  now.Add(time.Minute),
				Subject:  "tim",
				Done:     true,
			},
		},
		{
			name: "expired",
			args: args{
				ctx:        context.Background(),
				clientID:   "native",
				deviceCode: "expired",
			},
			want: &op.DeviceAuthorizationState{
				ClientID: "native",
				Scopes:   []string{"foo"},
				Expires:  now.Add(-time.Minute),
			},
			wantErr: oidc.ErrExpiredDeviceCode(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.CheckDeviceAuthorizationState(tt.args.ctx, tt.args.clientID, tt.args.deviceCode, testProvider)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCreateDeviceTokenResponse(t *testing.T) {
	tests := []struct {
		name             string
		tokenRequest     op.TokenRequest
		wantAccessToken  bool
		wantRefreshToken bool
		wantIDToken      bool
		wantErr          bool
	}{
		{
			name: "access token",
			tokenRequest: &op.DeviceAuthorizationState{
				ClientID: "client1",
				Subject:  "id1",
				AMR:      []string{"password"},
				AuthTime: time.Now(),
			},
			wantAccessToken: true,
		},
		{
			name: "access and refresh tokens",
			tokenRequest: &op.DeviceAuthorizationState{
				ClientID: "client1",
				Subject:  "id1",
				AMR:      []string{"password"},
				AuthTime: time.Now(),
				Scopes:   []string{oidc.ScopeOfflineAccess},
			},
			wantAccessToken:  true,
			wantRefreshToken: true,
		},
		{
			name: "access and id token",
			tokenRequest: &op.DeviceAuthorizationState{
				ClientID: "client1",
				Subject:  "id1",
				AMR:      []string{"password"},
				AuthTime: time.Now(),
				Scopes:   []string{oidc.ScopeOpenID},
			},
			wantAccessToken: true,
			wantIDToken:     true,
		},
		{
			name: "access, refresh and id token",
			tokenRequest: &op.DeviceAuthorizationState{
				ClientID: "client1",
				Subject:  "id1",
				AMR:      []string{"password"},
				AuthTime: time.Now(),
				Scopes:   []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
			},
			wantAccessToken:  true,
			wantRefreshToken: true,
			wantIDToken:      true,
		},
		{
			name: "id token creation error",
			tokenRequest: &op.DeviceAuthorizationState{
				ClientID: "client1",
				Subject:  "foobar",
				AMR:      []string{"password"},
				AuthTime: time.Now(),
				Scopes:   []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := testProvider.Storage().GetClientByClientID(context.Background(), "native")
			require.NoError(t, err)

			got, err := op.CreateDeviceTokenResponse(context.Background(), tt.tokenRequest, testProvider, client)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.InDelta(t, 300, got.ExpiresIn, 2)
			if tt.wantAccessToken {
				assert.NotEmpty(t, got.AccessToken, "access token")
			}
			if tt.wantRefreshToken {
				assert.NotEmpty(t, got.RefreshToken, "refresh token")
			}
			if tt.wantIDToken {
				assert.NotEmpty(t, got.IDToken, "id token")
			}
		})
	}
}

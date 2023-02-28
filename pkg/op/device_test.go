package op_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	mr "math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"
)

var testProvider op.OpenIDProvider

const (
	testIssuer    = "https://localhost:9998/"
	pathLoggedOut = "/logged-out"
)

func init() {
	config := &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		DefaultLogoutRedirectURI: pathLoggedOut,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormURL:  testIssuer + "device",
			UserCode:     op.UserCodeBase20,
		},
	}

	storage.RegisterClients(
		storage.NativeClient("native"),
		storage.WebClient("web", "secret"),
		storage.WebClient("api", "secret"),
	)

	var err error
	testProvider, err = op.NewOpenIDProvider(context.TODO(), testIssuer, config,
		storage.NewStorage(storage.NewUserStore(testIssuer)), op.WithAllowInsecure(),
	)
	if err != nil {
		panic(err)
	}
}

func Test_deviceAuthorizationHandler(t *testing.T) {
	req := &oidc.DeviceAuthorizationRequest{
		Scopes:   []string{"foo", "bar"},
		ClientID: "web",
	}
	values := make(url.Values)
	testProvider.Encoder().Encode(req, values)
	body := strings.NewReader(values.Encode())

	r := httptest.NewRequest(http.MethodPost, "/", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	runWithRandReader(mr.New(mr.NewSource(1)), func() {
		op.DeviceAuthorizationHandler(testProvider)(w, r)
	})

	result := w.Result()

	assert.Less(t, result.StatusCode, 300)

	got, _ := io.ReadAll(result.Body)
	assert.JSONEq(t, `{"device_code":"Uv38ByGCZU8WP18PmmIdcg", "expires_in":300, "interval":5, "user_code":"JKRV-FRGK", "verification_uri":"https://localhost:9998/device", "verification_uri_complete":"https://localhost:9998/device?user_code=JKRV-FRGK"}`, string(got))
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
		/* decoding a SpaceDelimitedArray is broken
		https://github.com/zitadel/oidc/issues/295
		{
			name: "success",
			req: &oidc.DeviceAuthorizationRequest{
				Scopes:   oidc.SpaceDelimitedArray{"foo", "bar"},
				ClientID: "web",
			},
		},
		*/
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
			} else {
				require.NoError(t, err)
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
	storage := testProvider.Storage().(op.DeviceAuthorizationStorage)
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

	storage := testProvider.Storage().(op.DeviceAuthorizationStorage)
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

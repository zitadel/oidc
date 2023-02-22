package op

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type DeviceAuthorizationConfig struct {
	Lifetime     int
	PollInterval int
	UserCode     UserCodeConfig
}

type UserCodeConfig struct {
	CharSet      string
	CharAmount   int
	DashInterval int
	QueryKey     string
	FormHTML     []byte
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
		QueryKey:     "user_code",
	}
	UserCodeDigits = UserCodeConfig{
		CharSet:      CharSetDigits,
		CharAmount:   9,
		DashInterval: 3,
		QueryKey:     "user_code",
	}
)

func deviceAuthorizationHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		DeviceAuthorization(w, r, o)
	}
}

func DeviceAuthorization(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	storage, ok := o.Storage().(DeviceCodeStorage)
	if !ok {
		// unimplemented error?
	}
	req, err := ParseDeviceCodeRequest(r, o.Decoder())
	if err != nil {
		RequestError(w, r, err)
		return
	}

	config := o.DeviceAuthorization()

	deviceCode, err := NewDeviceCode(RecommendedDeviceCodeBytes)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	userCode, err := NewUserCode([]rune(config.UserCode.CharSet), config.UserCode.CharAmount, config.UserCode.CharAmount)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	err = storage.StoreDeviceAuthorizationRequest(r.Context(), req, deviceCode, userCode)
	if err != nil {
		RequestError(w, r, err)
		return
	}

	endpoint := o.UserCodeFormEndpoint().Absolute(IssuerFromContext(r.Context()))

	response := &oidc.DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: endpoint,
	}

	if key := config.UserCode.QueryKey; key != "" {
		vals := make(url.Values, 1)
		vals.Set(key, userCode)
		response.VerificationURIComplete = strings.Join([]string{endpoint, vals.Encode()}, "?")
	}

	httphelper.MarshalJSON(w, response)
}

func ParseDeviceCodeRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.DeviceAuthorizationRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	devReq := new(oidc.DeviceAuthorizationRequest)
	if err := decoder.Decode(devReq, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse dev auth request").WithParent(err)
	}

	return devReq, nil
}

// 16 bytes gives 128 bit of entropy.
// results in a 22 character base64 encoded string.
const RecommendedDeviceCodeBytes = 16

func NewDeviceCode(nBytes int) (string, error) {
	bytes := make([]byte, nBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("%w getting entropy for device code", err)
	}
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
	req := new(oidc.DeviceAccessTokenRequest)
	if err := exchanger.Decoder().Decode(req, r.PostForm); err != nil {
		RequestError(w, r, err)
	}

	storage, ok := exchanger.Storage().(DeviceCodeStorage)
	if !ok {
		// unimplemented error?
	}

	client, err := storage.DeviceAccessPoll(r.Context(), req.DeviceCode)
	if err != nil {
		RequestError(w, r, err)
	}

	resp, err := CreateDeviceTokenResponse(r.Context(), req, exchanger, client)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	httphelper.MarshalJSON(w, resp)
}

func CreateDeviceTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator, client Client) (*oidc.AccessTokenResponse, error) {
	tokenType := AccessTokenTypeBearer // not sure if this is the correct type?

	accessToken, _, validity, err := CreateAccessToken(ctx, tokenRequest, tokenType, creator, client, "")
	if err != nil {
		return nil, err
	}

	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(validity.Seconds()),
	}, nil
}

func userCodeFormHandler(o OpenIDProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		UserCodeForm(w, r, o)
	}
}

func UserCodeForm(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	// check cookie, or what??

	config := o.DeviceAuthorization().UserCode
	userCode, err := UserCodeFromRequest(r, config.QueryKey)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	if userCode == "" {
		w.Write(config.FormHTML)
		return
	}

	storage, ok := o.Storage().(DeviceCodeStorage)
	if !ok {
		// unimplemented error?
	}

	if err := storage.ReleaseDeviceAccessToken(r.Context(), userCode); err != nil {
		RequestError(w, r, err)
		return
	}

	fmt.Fprintln(w, "Authorization successfull, please return to your device")
}

func UserCodeFromRequest(r *http.Request, key string) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	return r.Form.Get(key), nil
}

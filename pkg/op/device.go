package op

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type DeviceAuthorizationConfig struct {
	Lifetime     int
	PollInterval int
	UserFormURL  string
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

func deviceAuthorizationHandler(o OpenIDProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		DeviceAuthorization(w, r, o)
	}
}

func DeviceAuthorization(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	storage, err := assertDeviceStorage(o.Storage())
	if err != nil {
		RequestError(w, r, err)
		return
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
	err = storage.StoreDeviceAuthorization(r.Context(), req.ClientID, deviceCode, userCode, req.Scopes)
	if err != nil {
		RequestError(w, r, err)
		return
	}

	response := &oidc.DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: config.UserFormURL,
	}

	endpoint := o.UserCodeFormEndpoint().Absolute(IssuerFromContext(r.Context()))
	response.VerificationURIComplete = fmt.Sprintf("%s?user_code=%s", endpoint, userCode)

	httphelper.MarshalJSON(w, response)
}

func ParseDeviceCodeRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.DeviceAuthorizationRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	devReq := new(oidc.DeviceAuthorizationRequest)
	if err := decoder.Decode(devReq, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse device authentication request").WithParent(err)
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

type deviceAccessTokenRequest struct {
	subject  string
	audience []string
	scopes   []string
}

func (r *deviceAccessTokenRequest) GetSubject() string {
	return r.subject
}

func (r *deviceAccessTokenRequest) GetAudience() []string {
	return r.audience
}

func (r *deviceAccessTokenRequest) GetScopes() []string {
	return r.scopes
}

func DeviceAccessToken(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	req := new(oidc.DeviceAccessTokenRequest)
	if err := exchanger.Decoder().Decode(req, r.PostForm); err != nil {
		RequestError(w, r, err)
		return
	}

	// use a limited context timeout shorter as the default
	// poll interval of 5 seconds.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	state, err := CheckDeviceAuthorizationState(ctx, req, exchanger)
	if err != nil {
		RequestError(w, r, err)
		return
	}

	tokenRequest := &deviceAccessTokenRequest{
		subject:  state.Subject,
		audience: []string{req.ClientID},
		scopes:   state.Scopes,
	}

	resp, err := CreateDeviceTokenResponse(r.Context(), tokenRequest, exchanger, &jwtProfileClient{id: req.ClientID})
	if err != nil {
		RequestError(w, r, err)
		return
	}
	httphelper.MarshalJSON(w, resp)
}

func CheckDeviceAuthorizationState(ctx context.Context, req *oidc.DeviceAccessTokenRequest, exchanger Exchanger) (*DeviceAuthorizationState, error) {
	storage, err := assertDeviceStorage(exchanger.Storage())
	if err != nil {
		return nil, err
	}

	state, err := storage.GetDeviceAuthorizatonState(ctx, req.ClientID, req.DeviceCode)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, oidc.ErrSlowDown().WithParent(err)
	}
	if err != nil {
		return nil, err
	}
	if state.Denied {
		return state, oidc.ErrAccessDenied()
	}
	if state.Completed {
		return state, nil
	}
	if time.Now().After(state.Expires) {
		return state, oidc.ErrExpiredDeviceCode()
	}
	return state, oidc.ErrAuthorizationPending()
}

func CreateDeviceTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator, client AccessTokenClient) (*oidc.AccessTokenResponse, error) {
	tokenType := AccessTokenTypeBearer // not sure if this is the correct type?

	accessToken, refreshToken, validity, err := CreateAccessToken(ctx, tokenRequest, tokenType, creator, client, "")
	if err != nil {
		return nil, err
	}

	return &oidc.AccessTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    oidc.BearerToken,
		ExpiresIn:    uint64(validity.Seconds()),
	}, nil
}

func userCodeFormHandler(o OpenIDProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		UserCodeForm(w, r, o)
	}
}

type UserCodeFormData struct {
	AccesssToken string `schema:"access_token"`
	UserCode     string `schema:"user_code"`
	RedirectURL  string `schema:"redirect_url"`
}

func UserCodeForm(w http.ResponseWriter, r *http.Request, o OpenIDProvider) {
	data, err := ParseUserCodeFormData(r, o.Decoder())
	if err != nil {
		RequestError(w, r, err)
		return
	}

	storage, err := assertDeviceStorage(o.Storage())
	if err != nil {
		RequestError(w, r, err)
		return
	}

	ctx := r.Context()
	token, err := VerifyAccessToken(ctx, data.AccesssToken, o.AccessTokenVerifier(ctx))
	if err != nil {
		if se := storage.DenyDeviceAuthorization(ctx, data.UserCode); se != nil {
			err = se
		}
		RequestError(w, r, err)
		return
	}

	if err := storage.CompleteDeviceAuthorization(ctx, data.UserCode, token.GetSubject()); err != nil {
		RequestError(w, r, err)
		return
	}

	if data.RedirectURL != "" {
		http.Redirect(w, r, data.RedirectURL, http.StatusSeeOther)
	}

	fmt.Fprintln(w, "Authorization successfull, please return to your device")
}

func ParseUserCodeFormData(r *http.Request, decoder httphelper.Decoder) (*UserCodeFormData, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}

	req := new(UserCodeFormData)
	if err := decoder.Decode(req, r.Form); err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse user code form").WithParent(err)
	}
	if req.AccesssToken == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("access_token missing in form")
	}
	if req.UserCode == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("user_code missing in form")
	}

	return req, nil
}
package op_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
)

func TestGetTokenIDAndSubjectFromToken(t *testing.T) {
	tests := []struct {
		name string

		// args
		ctx       context.Context
		token     string
		tokenType oidc.TokenType
		isActor   bool
		exchanger op.Exchanger

		wantReturn []interface{}
	}{
		{
			name: "empty strings, nil and false if fails verify token actor",
			ctx:  context.Background(),
			token: func() string {
				tkn, err := op.NewAESCrypto([32]byte{0x01}).Encrypt("test:test:test")
				require.NoError(t, err)
				return tkn
			}(),
			tokenType: oidc.TokenType("unsupported_token_type"),
			isActor:   true,
			exchanger: func() op.Exchanger {
				type mStorage struct {
					op.Storage
					op.TokenExchangeTokensVerifierStorage
				}

				verifier := mock.NewMockTokenExchangeTokensVerifierStorage(gomock.NewController(t))
				verifier.
					EXPECT().
					VerifyExchangeActorToken(gomock.Any(), gomock.Any(), oidc.TokenType("unsupported_token_type")).
					Return("", "", nil, errors.New("actor verify error"))
				ms := mStorage{TokenExchangeTokensVerifierStorage: verifier}
				ex := mock.NewMockExchanger(gomock.NewController(t))
				ex.EXPECT().Storage().Return(ms)

				return ex
			}(),
			wantReturn: []interface{}{"", "", map[string]interface{}(nil), false},
		},
		{
			name: "empty strings, nil and false if fails verify token exchange subject",
			ctx:  context.Background(),
			token: func() string {
				tkn, err := op.NewAESCrypto([32]byte{0x01}).Encrypt("test:test:test")
				require.NoError(t, err)
				return tkn
			}(),
			tokenType: oidc.TokenType("unsupported_token_type"),
			isActor:   false,
			exchanger: func() op.Exchanger {
				type mStorage struct {
					op.Storage
					op.TokenExchangeTokensVerifierStorage
				}

				verifier := mock.NewMockTokenExchangeTokensVerifierStorage(gomock.NewController(t))
				verifier.
					EXPECT().
					VerifyExchangeSubjectToken(gomock.Any(), gomock.Any(), oidc.TokenType("unsupported_token_type")).
					Return("", "", nil, errors.New("actor verify error"))
				ms := mStorage{TokenExchangeTokensVerifierStorage: verifier}
				ex := mock.NewMockExchanger(gomock.NewController(t))
				ex.EXPECT().Storage().Return(ms)

				return ex
			}(),
			wantReturn: []interface{}{"", "", map[string]interface{}(nil), false},
		},
		{
			name: "empty strings, nil and false if exchanger storage is not TokenExchangeTokenVerifierStorage",
			ctx:  context.Background(),
			token: func() string {
				tkn, err := op.NewAESCrypto([32]byte{0x01}).Encrypt("test:test:test")
				require.NoError(t, err)
				return tkn
			}(),
			tokenType: oidc.TokenType("unsupported_token_type"),
			isActor:   false,
			exchanger: func() op.Exchanger {
				type mStorage struct {
					op.Storage
				}

				ms := mStorage{}
				ex := mock.NewMockExchanger(gomock.NewController(t))
				ex.EXPECT().Storage().Return(ms)

				return ex
			}(),
			wantReturn: []interface{}{"", "", map[string]interface{}(nil), false},
		},
		{
			name: "tokenId subject nil claims and true if success decrypt AccessTokenType",
			ctx:  context.Background(),
			token: func() string {
				tkn, err := op.NewAESCrypto([32]byte{0x01}).Encrypt("test:test")
				require.NoError(t, err)
				return tkn
			}(),
			tokenType: oidc.AccessTokenType,
			isActor:   true,
			exchanger: func() op.Exchanger {
				ex := mock.NewMockExchanger(gomock.NewController(t))
				ex.EXPECT().Crypto().Return(op.NewAESCrypto([32]byte{0x001}))
				return ex
			}(),
			wantReturn: []interface{}{"test", "test", map[string]interface{}(nil), true},
		},
		{
			name: "tokenId subject claims and true if success verify AccessTokenType claims",
			ctx:  context.Background(),
			// jwt.io sample token for RS256 with some extra claims
			token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiY2RlZiJ9.eyJqdGkiOiJ0ZXN0Iiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE3NDI4OTA4NjksImV4cCI6Mjc0Mjg5MDg2OSwiaXNzIjoiaXNzdWVyIn0.MpR3s7zrvwHUnis7Sc9C1-dZnDsXAsssJcdDWJY5cfhR7bXpwJs87GsUkdP-kVc1S3MDZg0Dl0ITLbAeu70Ix5E65o9wlUQM2QB2Nc3O16zWIWkHH9xhKf5mW-s1JRtNDqsy5hypl6S2l9zNSXSLhj96lMxyi4-4qfX2wsI8XN9sQk7oEgZt_Lcl-xiJtqZOKKyfA0zRqOCOPruaAIUJc5bo3dxmDRs9dILP1F7LYkarIH_DXDzOmqRT4UfHVdg7ZH2-yluXQvk24dFwtC2Vm9jut1Ecdihm4vBjvyokuPNw_5RC3nxlk14BPBcgsBNR9NVVo5SV6ATGI-9Uq2TR-Q",
			tokenType: oidc.AccessTokenType,
			isActor:   true,
			exchanger: func() op.Exchanger {
				c := mock.NewMockCrypto(gomock.NewController(t))
				c.EXPECT().
					Decrypt(gomock.Any()).
					Return("", errors.New("decrypt_error"))

				ex := mock.NewMockExchanger(gomock.NewController(t))
				ex.EXPECT().Crypto().Return(c)

				mockKey := mock.NewMockKey(gomock.NewController(t))
				mockKey.EXPECT().ID().Return("abcdef")
				mockKey.EXPECT().Algorithm().Return(jose.RS256)
				mockKey.EXPECT().Use().Return("sig")
				mockKey.EXPECT().Key().Return(getPublicKey())

				kStorage := mock.NewMockStorage(gomock.NewController(t))
				kStorage.EXPECT().KeySet(gomock.Any()).Return([]op.Key{mockKey}, nil)
				v := op.AccessTokenVerifier(oidc.Verifier{
					Issuer:            "issuer",
					SupportedSignAlgs: []string{string(jose.RS256)},
					KeySet: &op.OpenIDKeySet{
						Storage: kStorage,
					},
					Offset: 5000 * time.Minute,
				})
				ex.EXPECT().AccessTokenVerifier(gomock.Any()).Return(&v)
				return ex
			}(),
			wantReturn: []interface{}{"test", "1234567890", map[string]interface{}{
				"admin": true,
				"exp":   float64(2742890869),
				"iat":   float64(1742890869),
				"iss":   "issuer",
				"name":  "John Doe",
				"jti":   "test",
				"sub":   "1234567890",
			}, true},
		},
		{
			name: "token subject and nil claims if success handling refresh token type",
			ctx:  context.Background(),
			// jwt.io sample token for RS256 with some extra claims
			token:     "test",
			tokenType: oidc.RefreshTokenType,
			isActor:   true,
			exchanger: func() op.Exchanger {
				rt := mock.NewMockRefreshTokenRequest(gomock.NewController(t))
				rt.EXPECT().GetSubject().Return("1234567890")
				st := mock.NewMockStorage(gomock.NewController(t))
				st.EXPECT().
					TokenRequestByRefreshToken(gomock.Any(), "test").
					Return(rt, nil)
				ex := mock.NewMockExchanger(gomock.NewController(t))
				ex.EXPECT().Storage().Return(st)
				return ex
			}(),
			wantReturn: []interface{}{"test", "1234567890", map[string]interface{}(nil), true},
		},
		{
			name: "token subject and tokenclaims if success handling id token type",
			ctx:  context.Background(),
			// jwt.io sample token for RS256 with some extra claims
			token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiY2RlZiJ9.eyJqdGkiOiJ0ZXN0Iiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE3NDI4OTA4NjksImV4cCI6Mjc0Mjg5MDg2OSwiaXNzIjoiaXNzdWVyIn0.MpR3s7zrvwHUnis7Sc9C1-dZnDsXAsssJcdDWJY5cfhR7bXpwJs87GsUkdP-kVc1S3MDZg0Dl0ITLbAeu70Ix5E65o9wlUQM2QB2Nc3O16zWIWkHH9xhKf5mW-s1JRtNDqsy5hypl6S2l9zNSXSLhj96lMxyi4-4qfX2wsI8XN9sQk7oEgZt_Lcl-xiJtqZOKKyfA0zRqOCOPruaAIUJc5bo3dxmDRs9dILP1F7LYkarIH_DXDzOmqRT4UfHVdg7ZH2-yluXQvk24dFwtC2Vm9jut1Ecdihm4vBjvyokuPNw_5RC3nxlk14BPBcgsBNR9NVVo5SV6ATGI-9Uq2TR-Q",
			tokenType: oidc.IDTokenType,
			isActor:   true,
			exchanger: func() op.Exchanger {
				mockKey := mock.NewMockKey(gomock.NewController(t))
				mockKey.EXPECT().ID().Return("abcdef")
				mockKey.EXPECT().Algorithm().Return(jose.RS256)
				mockKey.EXPECT().Use().Return("sig")
				mockKey.EXPECT().Key().Return(getPublicKey())

				kStorage := mock.NewMockStorage(gomock.NewController(t))
				kStorage.EXPECT().KeySet(gomock.Any()).Return([]op.Key{mockKey}, nil)
				v := &op.IDTokenHintVerifier{
					Issuer:            "issuer",
					SupportedSignAlgs: []string{string(jose.RS256)},
					KeySet: &op.OpenIDKeySet{
						Storage: kStorage,
					},
					Offset: 5000 * time.Minute,
				}
				ex := mock.NewMockExchanger(gomock.NewController(t))
				ex.EXPECT().IDTokenHintVerifier(gomock.Any()).Return(v)
				return ex
			}(),
			wantReturn: []interface{}{
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiY2RlZiJ9.eyJqdGkiOiJ0ZXN0Iiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE3NDI4OTA4NjksImV4cCI6Mjc0Mjg5MDg2OSwiaXNzIjoiaXNzdWVyIn0.MpR3s7zrvwHUnis7Sc9C1-dZnDsXAsssJcdDWJY5cfhR7bXpwJs87GsUkdP-kVc1S3MDZg0Dl0ITLbAeu70Ix5E65o9wlUQM2QB2Nc3O16zWIWkHH9xhKf5mW-s1JRtNDqsy5hypl6S2l9zNSXSLhj96lMxyi4-4qfX2wsI8XN9sQk7oEgZt_Lcl-xiJtqZOKKyfA0zRqOCOPruaAIUJc5bo3dxmDRs9dILP1F7LYkarIH_DXDzOmqRT4UfHVdg7ZH2-yluXQvk24dFwtC2Vm9jut1Ecdihm4vBjvyokuPNw_5RC3nxlk14BPBcgsBNR9NVVo5SV6ATGI-9Uq2TR-Q",
				"1234567890",
				map[string]interface{}{
					"admin": true,
					"exp":   float64(2742890869),
					"iat":   float64(1742890869),
					"iss":   "issuer",
					"name":  "John Doe",
					"jti":   "test",
					"sub":   "1234567890",
				},
				true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenIdOrToken, subject, claims, ok := op.GetTokenIDAndSubjectFromToken(
				tt.ctx,
				tt.exchanger,
				tt.token,
				tt.tokenType,
				tt.isActor,
			)

			assert.Equal(t, tt.wantReturn[0].(string), tokenIdOrToken)
			assert.Equal(t, tt.wantReturn[1].(string), subject)
			assert.Equal(t, tt.wantReturn[2], claims)
			assert.Equal(t, tt.wantReturn[3].(bool), ok)
		})
	}
}

func getPublicKey() *rsa.PublicKey {
	// jwt.io sample public key for RS256
	spkiPem := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`
	spkiBlock, _ := pem.Decode([]byte(spkiPem))
	var spkiKey *rsa.PublicKey
	pubInterface, _ := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	spkiKey = pubInterface.(*rsa.PublicKey)
	return spkiKey
}

package mock

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/schema"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
	"github.com/caos/oidc/pkg/rp"
)

func NewAuthorizer(t *testing.T) op.Authorizer {
	return NewMockAuthorizer(gomock.NewController(t))
}

func NewAuthorizerExpectValid(t *testing.T, wantErr bool) op.Authorizer {
	m := NewAuthorizer(t)
	ExpectDecoder(m)
	ExpectEncoder(m)
	ExpectSigner(m, t)
	ExpectStorage(m, t)
	ExpectVerifier(m, t)
	// ExpectErrorHandler(m, t, wantErr)
	return m
}

// func NewAuthorizerExpectDecoderFails(t *testing.T) op.Authorizer {
// 	m := NewAuthorizer(t)
// 	ExpectDecoderFails(m)
// 	ExpectEncoder(m)
// 	ExpectSigner(m, t)
// 	ExpectStorage(m, t)
// 	ExpectErrorHandler(m, t)
// 	return m
// }

func ExpectDecoder(a op.Authorizer) {
	mockA := a.(*MockAuthorizer)
	mockA.EXPECT().Decoder().AnyTimes().Return(schema.NewDecoder())
}

func ExpectEncoder(a op.Authorizer) {
	mockA := a.(*MockAuthorizer)
	mockA.EXPECT().Encoder().AnyTimes().Return(schema.NewEncoder())
}

func ExpectSigner(a op.Authorizer, t *testing.T) {
	mockA := a.(*MockAuthorizer)
	mockA.EXPECT().Signer().DoAndReturn(
		func() op.Signer {
			return &Sig{}
		})
}

func ExpectVerifier(a op.Authorizer, t *testing.T) {
	mockA := a.(*MockAuthorizer)
	mockA.EXPECT().IDTokenVerifier().DoAndReturn(
		func() rp.Verifier {
			return &Verifier{}
		})
}

type Verifier struct{}

func (v *Verifier) Verify(ctx context.Context, accessToken, idToken string) (*oidc.IDTokenClaims, error) {
	return nil, nil
}

type Sig struct{}

func (s *Sig) Health(ctx context.Context) error {
	return nil
}

func (s *Sig) SignIDToken(*oidc.IDTokenClaims) (string, error) {
	return "", nil
}
func (s *Sig) SignAccessToken(*oidc.AccessTokenClaims) (string, error) {
	return "", nil
}
func (s *Sig) SignatureAlgorithm() jose.SignatureAlgorithm {
	return jose.HS256
}

func ExpectStorage(a op.Authorizer, t *testing.T) {
	mockA := a.(*MockAuthorizer)
	mockA.EXPECT().Storage().AnyTimes().Return(NewMockStorageAny(t))
}

// func NewMockSignerAny(t *testing.T) op.Signer {
// 	m := NewMockSigner(gomock.NewController(t))
// 	m.EXPECT().Sign(gomock.Any()).AnyTimes().Return("", nil)
// 	return m
// }

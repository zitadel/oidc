package mock

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/rp"
)

func NewVerifier(t *testing.T) rp.Verifier {
	return NewMockVerifier(gomock.NewController(t))
}

func NewMockVerifierExpectInvalid(t *testing.T) rp.Verifier {
	m := NewVerifier(t)
	ExpectVerifyInvalid(m)
	return m
}

func ExpectVerifyInvalid(v rp.Verifier) {
	mock := v.(*MockVerifier)
	mock.EXPECT().VerifyIdToken(gomock.Any(), gomock.Any()).Return(nil, errors.New("invalid"))
}

func NewMockVerifierExpectValid(t *testing.T) rp.Verifier {
	m := NewVerifier(t)
	ExpectVerifyValid(m)
	return m
}

func ExpectVerifyValid(v rp.Verifier) {
	mock := v.(*MockVerifier)
	mock.EXPECT().VerifyIdToken(gomock.Any(), gomock.Any()).Return(&oidc.IDTokenClaims{Userinfo: oidc.Userinfo{Subject: "id"}}, nil)
}

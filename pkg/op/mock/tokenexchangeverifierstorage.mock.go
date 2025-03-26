// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/zitadel/oidc/v3/pkg/op (interfaces: TokenExchangeTokensVerifierStorage)

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	oidc "github.com/zitadel/oidc/v3/pkg/oidc"
)

// MockTokenExchangeTokensVerifierStorage is a mock of TokenExchangeTokensVerifierStorage interface.
type MockTokenExchangeTokensVerifierStorage struct {
	ctrl     *gomock.Controller
	recorder *MockTokenExchangeTokensVerifierStorageMockRecorder
}

// MockTokenExchangeTokensVerifierStorageMockRecorder is the mock recorder for MockTokenExchangeTokensVerifierStorage.
type MockTokenExchangeTokensVerifierStorageMockRecorder struct {
	mock *MockTokenExchangeTokensVerifierStorage
}

// NewMockTokenExchangeTokensVerifierStorage creates a new mock instance.
func NewMockTokenExchangeTokensVerifierStorage(ctrl *gomock.Controller) *MockTokenExchangeTokensVerifierStorage {
	mock := &MockTokenExchangeTokensVerifierStorage{ctrl: ctrl}
	mock.recorder = &MockTokenExchangeTokensVerifierStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTokenExchangeTokensVerifierStorage) EXPECT() *MockTokenExchangeTokensVerifierStorageMockRecorder {
	return m.recorder
}

// VerifyExchangeActorToken mocks base method.
func (m *MockTokenExchangeTokensVerifierStorage) VerifyExchangeActorToken(arg0 context.Context, arg1 string, arg2 oidc.TokenType) (string, string, map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyExchangeActorToken", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(map[string]interface{})
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// VerifyExchangeActorToken indicates an expected call of VerifyExchangeActorToken.
func (mr *MockTokenExchangeTokensVerifierStorageMockRecorder) VerifyExchangeActorToken(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyExchangeActorToken", reflect.TypeOf((*MockTokenExchangeTokensVerifierStorage)(nil).VerifyExchangeActorToken), arg0, arg1, arg2)
}

// VerifyExchangeSubjectToken mocks base method.
func (m *MockTokenExchangeTokensVerifierStorage) VerifyExchangeSubjectToken(arg0 context.Context, arg1 string, arg2 oidc.TokenType) (string, string, map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyExchangeSubjectToken", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(map[string]interface{})
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// VerifyExchangeSubjectToken indicates an expected call of VerifyExchangeSubjectToken.
func (mr *MockTokenExchangeTokensVerifierStorageMockRecorder) VerifyExchangeSubjectToken(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyExchangeSubjectToken", reflect.TypeOf((*MockTokenExchangeTokensVerifierStorage)(nil).VerifyExchangeSubjectToken), arg0, arg1, arg2)
}

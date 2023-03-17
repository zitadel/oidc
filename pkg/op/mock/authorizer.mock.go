// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/zitadel/oidc/v3/pkg/op (interfaces: Authorizer)

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	http "github.com/zitadel/oidc/v3/pkg/http"
	op "github.com/zitadel/oidc/v3/pkg/op"
)

// MockAuthorizer is a mock of Authorizer interface.
type MockAuthorizer struct {
	ctrl     *gomock.Controller
	recorder *MockAuthorizerMockRecorder
}

// MockAuthorizerMockRecorder is the mock recorder for MockAuthorizer.
type MockAuthorizerMockRecorder struct {
	mock *MockAuthorizer
}

// NewMockAuthorizer creates a new mock instance.
func NewMockAuthorizer(ctrl *gomock.Controller) *MockAuthorizer {
	mock := &MockAuthorizer{ctrl: ctrl}
	mock.recorder = &MockAuthorizerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthorizer) EXPECT() *MockAuthorizerMockRecorder {
	return m.recorder
}

// Crypto mocks base method.
func (m *MockAuthorizer) Crypto() op.Crypto {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Crypto")
	ret0, _ := ret[0].(op.Crypto)
	return ret0
}

// Crypto indicates an expected call of Crypto.
func (mr *MockAuthorizerMockRecorder) Crypto() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Crypto", reflect.TypeOf((*MockAuthorizer)(nil).Crypto))
}

// Decoder mocks base method.
func (m *MockAuthorizer) Decoder() http.Decoder {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Decoder")
	ret0, _ := ret[0].(http.Decoder)
	return ret0
}

// Decoder indicates an expected call of Decoder.
func (mr *MockAuthorizerMockRecorder) Decoder() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decoder", reflect.TypeOf((*MockAuthorizer)(nil).Decoder))
}

// Encoder mocks base method.
func (m *MockAuthorizer) Encoder() http.Encoder {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Encoder")
	ret0, _ := ret[0].(http.Encoder)
	return ret0
}

// Encoder indicates an expected call of Encoder.
func (mr *MockAuthorizerMockRecorder) Encoder() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encoder", reflect.TypeOf((*MockAuthorizer)(nil).Encoder))
}

// IDTokenHintVerifier mocks base method.
func (m *MockAuthorizer) IDTokenHintVerifier(arg0 context.Context) op.IDTokenHintVerifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IDTokenHintVerifier", arg0)
	ret0, _ := ret[0].(op.IDTokenHintVerifier)
	return ret0
}

// IDTokenHintVerifier indicates an expected call of IDTokenHintVerifier.
func (mr *MockAuthorizerMockRecorder) IDTokenHintVerifier(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IDTokenHintVerifier", reflect.TypeOf((*MockAuthorizer)(nil).IDTokenHintVerifier), arg0)
}

// RequestObjectSupported mocks base method.
func (m *MockAuthorizer) RequestObjectSupported() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestObjectSupported")
	ret0, _ := ret[0].(bool)
	return ret0
}

// RequestObjectSupported indicates an expected call of RequestObjectSupported.
func (mr *MockAuthorizerMockRecorder) RequestObjectSupported() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestObjectSupported", reflect.TypeOf((*MockAuthorizer)(nil).RequestObjectSupported))
}

// Storage mocks base method.
func (m *MockAuthorizer) Storage() op.Storage {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Storage")
	ret0, _ := ret[0].(op.Storage)
	return ret0
}

// Storage indicates an expected call of Storage.
func (mr *MockAuthorizerMockRecorder) Storage() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Storage", reflect.TypeOf((*MockAuthorizer)(nil).Storage))
}

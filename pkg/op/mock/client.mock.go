// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/caos/oidc/pkg/op (interfaces: Client)

// Package mock is a generated GoMock package.
package mock

import (
	oidc "github.com/caos/oidc/pkg/oidc"
	op "github.com/caos/oidc/pkg/op"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
	time "time"
)

// MockClient is a mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// AccessTokenType mocks base method
func (m *MockClient) AccessTokenType() op.AccessTokenType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AccessTokenType")
	ret0, _ := ret[0].(op.AccessTokenType)
	return ret0
}

// AccessTokenType indicates an expected call of AccessTokenType
func (mr *MockClientMockRecorder) AccessTokenType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AccessTokenType", reflect.TypeOf((*MockClient)(nil).AccessTokenType))
}

// ApplicationType mocks base method
func (m *MockClient) ApplicationType() op.ApplicationType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ApplicationType")
	ret0, _ := ret[0].(op.ApplicationType)
	return ret0
}

// ApplicationType indicates an expected call of ApplicationType
func (mr *MockClientMockRecorder) ApplicationType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ApplicationType", reflect.TypeOf((*MockClient)(nil).ApplicationType))
}

// AssertAdditionalAccessTokenScopes mocks base method
func (m *MockClient) AssertAdditionalAccessTokenScopes() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssertAdditionalAccessTokenScopes")
	ret0, _ := ret[0].(bool)
	return ret0
}

// AssertAdditionalAccessTokenScopes indicates an expected call of AssertAdditionalAccessTokenScopes
func (mr *MockClientMockRecorder) AssertAdditionalAccessTokenScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssertAdditionalAccessTokenScopes", reflect.TypeOf((*MockClient)(nil).AssertAdditionalAccessTokenScopes))
}

// AssertAdditionalIdTokenScopes mocks base method
func (m *MockClient) AssertAdditionalIdTokenScopes() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssertAdditionalIdTokenScopes")
	ret0, _ := ret[0].(bool)
	return ret0
}

// AssertAdditionalIdTokenScopes indicates an expected call of AssertAdditionalIdTokenScopes
func (mr *MockClientMockRecorder) AssertAdditionalIdTokenScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssertAdditionalIdTokenScopes", reflect.TypeOf((*MockClient)(nil).AssertAdditionalIdTokenScopes))
}

// AuthMethod mocks base method
func (m *MockClient) AuthMethod() op.AuthMethod {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthMethod")
	ret0, _ := ret[0].(op.AuthMethod)
	return ret0
}

// AuthMethod indicates an expected call of AuthMethod
func (mr *MockClientMockRecorder) AuthMethod() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthMethod", reflect.TypeOf((*MockClient)(nil).AuthMethod))
}

// DevMode mocks base method
func (m *MockClient) DevMode() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DevMode")
	ret0, _ := ret[0].(bool)
	return ret0
}

// DevMode indicates an expected call of DevMode
func (mr *MockClientMockRecorder) DevMode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DevMode", reflect.TypeOf((*MockClient)(nil).DevMode))
}

// GetID mocks base method
func (m *MockClient) GetID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetID indicates an expected call of GetID
func (mr *MockClientMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockClient)(nil).GetID))
}

// IDTokenLifetime mocks base method
func (m *MockClient) IDTokenLifetime() time.Duration {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IDTokenLifetime")
	ret0, _ := ret[0].(time.Duration)
	return ret0
}

// IDTokenLifetime indicates an expected call of IDTokenLifetime
func (mr *MockClientMockRecorder) IDTokenLifetime() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IDTokenLifetime", reflect.TypeOf((*MockClient)(nil).IDTokenLifetime))
}

// IsScopeAllowed mocks base method
func (m *MockClient) IsScopeAllowed(arg0 string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsScopeAllowed", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsScopeAllowed indicates an expected call of IsScopeAllowed
func (mr *MockClientMockRecorder) IsScopeAllowed(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsScopeAllowed", reflect.TypeOf((*MockClient)(nil).IsScopeAllowed), arg0)
}

// LoginURL mocks base method
func (m *MockClient) LoginURL(arg0 string) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LoginURL", arg0)
	ret0, _ := ret[0].(string)
	return ret0
}

// LoginURL indicates an expected call of LoginURL
func (mr *MockClientMockRecorder) LoginURL(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoginURL", reflect.TypeOf((*MockClient)(nil).LoginURL), arg0)
}

// PostLogoutRedirectURIs mocks base method
func (m *MockClient) PostLogoutRedirectURIs() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostLogoutRedirectURIs")
	ret0, _ := ret[0].([]string)
	return ret0
}

// PostLogoutRedirectURIs indicates an expected call of PostLogoutRedirectURIs
func (mr *MockClientMockRecorder) PostLogoutRedirectURIs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostLogoutRedirectURIs", reflect.TypeOf((*MockClient)(nil).PostLogoutRedirectURIs))
}

// RedirectURIs mocks base method
func (m *MockClient) RedirectURIs() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RedirectURIs")
	ret0, _ := ret[0].([]string)
	return ret0
}

// RedirectURIs indicates an expected call of RedirectURIs
func (mr *MockClientMockRecorder) RedirectURIs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RedirectURIs", reflect.TypeOf((*MockClient)(nil).RedirectURIs))
}

// ResponseTypes mocks base method
func (m *MockClient) ResponseTypes() []oidc.ResponseType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResponseTypes")
	ret0, _ := ret[0].([]oidc.ResponseType)
	return ret0
}

// ResponseTypes indicates an expected call of ResponseTypes
func (mr *MockClientMockRecorder) ResponseTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResponseTypes", reflect.TypeOf((*MockClient)(nil).ResponseTypes))
}

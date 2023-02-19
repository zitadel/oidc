// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/zitadel/oidc/v2/pkg/op (interfaces: Client)

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	oidc "github.com/zitadel/oidc/v2/pkg/oidc"
	op "github.com/zitadel/oidc/v2/pkg/op"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// AccessTokenType mocks base method.
func (m *MockClient) AccessTokenType() op.AccessTokenType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AccessTokenType")
	ret0, _ := ret[0].(op.AccessTokenType)
	return ret0
}

// AccessTokenType indicates an expected call of AccessTokenType.
func (mr *MockClientMockRecorder) AccessTokenType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AccessTokenType", reflect.TypeOf((*MockClient)(nil).AccessTokenType))
}

// ApplicationType mocks base method.
func (m *MockClient) ApplicationType() op.ApplicationType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ApplicationType")
	ret0, _ := ret[0].(op.ApplicationType)
	return ret0
}

// ApplicationType indicates an expected call of ApplicationType.
func (mr *MockClientMockRecorder) ApplicationType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ApplicationType", reflect.TypeOf((*MockClient)(nil).ApplicationType))
}

// AuthMethod mocks base method.
func (m *MockClient) AuthMethod() oidc.AuthMethod {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthMethod")
	ret0, _ := ret[0].(oidc.AuthMethod)
	return ret0
}

// AuthMethod indicates an expected call of AuthMethod.
func (mr *MockClientMockRecorder) AuthMethod() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthMethod", reflect.TypeOf((*MockClient)(nil).AuthMethod))
}

// ClockSkew mocks base method.
func (m *MockClient) ClockSkew() time.Duration {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClockSkew")
	ret0, _ := ret[0].(time.Duration)
	return ret0
}

// ClockSkew indicates an expected call of ClockSkew.
func (mr *MockClientMockRecorder) ClockSkew() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClockSkew", reflect.TypeOf((*MockClient)(nil).ClockSkew))
}

// DevMode mocks base method.
func (m *MockClient) DevMode() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DevMode")
	ret0, _ := ret[0].(bool)
	return ret0
}

// DevMode indicates an expected call of DevMode.
func (mr *MockClientMockRecorder) DevMode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DevMode", reflect.TypeOf((*MockClient)(nil).DevMode))
}

// GetID mocks base method.
func (m *MockClient) GetID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetID indicates an expected call of GetID.
func (mr *MockClientMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockClient)(nil).GetID))
}

// GrantTypes mocks base method.
func (m *MockClient) GrantTypes() []oidc.GrantType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GrantTypes")
	ret0, _ := ret[0].([]oidc.GrantType)
	return ret0
}

// GrantTypes indicates an expected call of GrantTypes.
func (mr *MockClientMockRecorder) GrantTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantTypes", reflect.TypeOf((*MockClient)(nil).GrantTypes))
}

// IDTokenLifetime mocks base method.
func (m *MockClient) IDTokenLifetime() time.Duration {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IDTokenLifetime")
	ret0, _ := ret[0].(time.Duration)
	return ret0
}

// IDTokenLifetime indicates an expected call of IDTokenLifetime.
func (mr *MockClientMockRecorder) IDTokenLifetime() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IDTokenLifetime", reflect.TypeOf((*MockClient)(nil).IDTokenLifetime))
}

// IDTokenUserinfoClaimsAssertion mocks base method.
func (m *MockClient) IDTokenUserinfoClaimsAssertion() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IDTokenUserinfoClaimsAssertion")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IDTokenUserinfoClaimsAssertion indicates an expected call of IDTokenUserinfoClaimsAssertion.
func (mr *MockClientMockRecorder) IDTokenUserinfoClaimsAssertion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IDTokenUserinfoClaimsAssertion", reflect.TypeOf((*MockClient)(nil).IDTokenUserinfoClaimsAssertion))
}

// IsScopeAllowed mocks base method.
func (m *MockClient) IsScopeAllowed(arg0 string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsScopeAllowed", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsScopeAllowed indicates an expected call of IsScopeAllowed.
func (mr *MockClientMockRecorder) IsScopeAllowed(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsScopeAllowed", reflect.TypeOf((*MockClient)(nil).IsScopeAllowed), arg0)
}

// LoginURL mocks base method.
func (m *MockClient) LoginURL(arg0 string) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LoginURL", arg0)
	ret0, _ := ret[0].(string)
	return ret0
}

// LoginURL indicates an expected call of LoginURL.
func (mr *MockClientMockRecorder) LoginURL(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoginURL", reflect.TypeOf((*MockClient)(nil).LoginURL), arg0)
}

// PostLogoutRedirectURIs mocks base method.
func (m *MockClient) PostLogoutRedirectURIs() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostLogoutRedirectURIs")
	ret0, _ := ret[0].([]string)
	return ret0
}

// PostLogoutRedirectURIs indicates an expected call of PostLogoutRedirectURIs.
func (mr *MockClientMockRecorder) PostLogoutRedirectURIs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostLogoutRedirectURIs", reflect.TypeOf((*MockClient)(nil).PostLogoutRedirectURIs))
}

// RedirectURIs mocks base method.
func (m *MockClient) RedirectURIs() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RedirectURIs")
	ret0, _ := ret[0].([]string)
	return ret0
}

// RedirectURIs indicates an expected call of RedirectURIs.
func (mr *MockClientMockRecorder) RedirectURIs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RedirectURIs", reflect.TypeOf((*MockClient)(nil).RedirectURIs))
}

// ResponseTypes mocks base method.
func (m *MockClient) ResponseTypes() []oidc.ResponseType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResponseTypes")
	ret0, _ := ret[0].([]oidc.ResponseType)
	return ret0
}

// ResponseTypes indicates an expected call of ResponseTypes.
func (mr *MockClientMockRecorder) ResponseTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResponseTypes", reflect.TypeOf((*MockClient)(nil).ResponseTypes))
}

// RestrictAdditionalAccessTokenScopes mocks base method.
func (m *MockClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RestrictAdditionalAccessTokenScopes")
	ret0, _ := ret[0].(func([]string) []string)
	return ret0
}

// RestrictAdditionalAccessTokenScopes indicates an expected call of RestrictAdditionalAccessTokenScopes.
func (mr *MockClientMockRecorder) RestrictAdditionalAccessTokenScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestrictAdditionalAccessTokenScopes", reflect.TypeOf((*MockClient)(nil).RestrictAdditionalAccessTokenScopes))
}

// RestrictAdditionalIdTokenScopes mocks base method.
func (m *MockClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RestrictAdditionalIdTokenScopes")
	ret0, _ := ret[0].(func([]string) []string)
	return ret0
}

// RestrictAdditionalIdTokenScopes indicates an expected call of RestrictAdditionalIdTokenScopes.
func (mr *MockClientMockRecorder) RestrictAdditionalIdTokenScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestrictAdditionalIdTokenScopes", reflect.TypeOf((*MockClient)(nil).RestrictAdditionalIdTokenScopes))
}

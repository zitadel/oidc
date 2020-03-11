// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/caos/oidc/pkg/op (interfaces: Storage)

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	oidc "github.com/caos/oidc/pkg/oidc"
	op "github.com/caos/oidc/pkg/op"
	gomock "github.com/golang/mock/gomock"
	go_jose_v2 "gopkg.in/square/go-jose.v2"
	reflect "reflect"
	time "time"
)

// MockStorage is a mock of Storage interface
type MockStorage struct {
	ctrl     *gomock.Controller
	recorder *MockStorageMockRecorder
}

// MockStorageMockRecorder is the mock recorder for MockStorage
type MockStorageMockRecorder struct {
	mock *MockStorage
}

// NewMockStorage creates a new mock instance
func NewMockStorage(ctrl *gomock.Controller) *MockStorage {
	mock := &MockStorage{ctrl: ctrl}
	mock.recorder = &MockStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockStorage) EXPECT() *MockStorageMockRecorder {
	return m.recorder
}

// AuthRequestByID mocks base method
func (m *MockStorage) AuthRequestByID(arg0 context.Context, arg1 string) (op.AuthRequest, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthRequestByID", arg0, arg1)
	ret0, _ := ret[0].(op.AuthRequest)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthRequestByID indicates an expected call of AuthRequestByID
func (mr *MockStorageMockRecorder) AuthRequestByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthRequestByID", reflect.TypeOf((*MockStorage)(nil).AuthRequestByID), arg0, arg1)
}

// AuthorizeClientIDSecret mocks base method
func (m *MockStorage) AuthorizeClientIDSecret(arg0 context.Context, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizeClientIDSecret", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AuthorizeClientIDSecret indicates an expected call of AuthorizeClientIDSecret
func (mr *MockStorageMockRecorder) AuthorizeClientIDSecret(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizeClientIDSecret", reflect.TypeOf((*MockStorage)(nil).AuthorizeClientIDSecret), arg0, arg1, arg2)
}

// CreateAuthRequest mocks base method
func (m *MockStorage) CreateAuthRequest(arg0 context.Context, arg1 *oidc.AuthRequest, arg2 string) (op.AuthRequest, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAuthRequest", arg0, arg1, arg2)
	ret0, _ := ret[0].(op.AuthRequest)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAuthRequest indicates an expected call of CreateAuthRequest
func (mr *MockStorageMockRecorder) CreateAuthRequest(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthRequest", reflect.TypeOf((*MockStorage)(nil).CreateAuthRequest), arg0, arg1, arg2)
}

// CreateToken mocks base method
func (m *MockStorage) CreateToken(arg0 context.Context, arg1 op.AuthRequest) (string, time.Time, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateToken", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(time.Time)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateToken indicates an expected call of CreateToken
func (mr *MockStorageMockRecorder) CreateToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateToken", reflect.TypeOf((*MockStorage)(nil).CreateToken), arg0, arg1)
}

// DeleteAuthRequest mocks base method
func (m *MockStorage) DeleteAuthRequest(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAuthRequest", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAuthRequest indicates an expected call of DeleteAuthRequest
func (mr *MockStorageMockRecorder) DeleteAuthRequest(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAuthRequest", reflect.TypeOf((*MockStorage)(nil).DeleteAuthRequest), arg0, arg1)
}

// GetClientByClientID mocks base method
func (m *MockStorage) GetClientByClientID(arg0 context.Context, arg1 string) (op.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClientByClientID", arg0, arg1)
	ret0, _ := ret[0].(op.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClientByClientID indicates an expected call of GetClientByClientID
func (mr *MockStorageMockRecorder) GetClientByClientID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClientByClientID", reflect.TypeOf((*MockStorage)(nil).GetClientByClientID), arg0, arg1)
}

// GetKeySet mocks base method
func (m *MockStorage) GetKeySet(arg0 context.Context) (*go_jose_v2.JSONWebKeySet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKeySet", arg0)
	ret0, _ := ret[0].(*go_jose_v2.JSONWebKeySet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetKeySet indicates an expected call of GetKeySet
func (mr *MockStorageMockRecorder) GetKeySet(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKeySet", reflect.TypeOf((*MockStorage)(nil).GetKeySet), arg0)
}

// GetSigningKey mocks base method
func (m *MockStorage) GetSigningKey(arg0 context.Context, arg1 chan<- go_jose_v2.SigningKey, arg2 chan<- error, arg3 <-chan time.Time) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GetSigningKey", arg0, arg1, arg2, arg3)
}

// GetSigningKey indicates an expected call of GetSigningKey
func (mr *MockStorageMockRecorder) GetSigningKey(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSigningKey", reflect.TypeOf((*MockStorage)(nil).GetSigningKey), arg0, arg1, arg2, arg3)
}

// GetUserinfoFromScopes mocks base method
func (m *MockStorage) GetUserinfoFromScopes(arg0 context.Context, arg1 string, arg2 []string) (*oidc.Userinfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserinfoFromScopes", arg0, arg1, arg2)
	ret0, _ := ret[0].(*oidc.Userinfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserinfoFromScopes indicates an expected call of GetUserinfoFromScopes
func (mr *MockStorageMockRecorder) GetUserinfoFromScopes(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserinfoFromScopes", reflect.TypeOf((*MockStorage)(nil).GetUserinfoFromScopes), arg0, arg1, arg2)
}

// GetUserinfoFromToken mocks base method
func (m *MockStorage) GetUserinfoFromToken(arg0 context.Context, arg1 string) (*oidc.Userinfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserinfoFromToken", arg0, arg1)
	ret0, _ := ret[0].(*oidc.Userinfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserinfoFromToken indicates an expected call of GetUserinfoFromToken
func (mr *MockStorageMockRecorder) GetUserinfoFromToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserinfoFromToken", reflect.TypeOf((*MockStorage)(nil).GetUserinfoFromToken), arg0, arg1)
}

// Health mocks base method
func (m *MockStorage) Health(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Health", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Health indicates an expected call of Health
func (mr *MockStorageMockRecorder) Health(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Health", reflect.TypeOf((*MockStorage)(nil).Health), arg0)
}

// SaveNewKeyPair mocks base method
func (m *MockStorage) SaveNewKeyPair(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveNewKeyPair", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveNewKeyPair indicates an expected call of SaveNewKeyPair
func (mr *MockStorageMockRecorder) SaveNewKeyPair(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveNewKeyPair", reflect.TypeOf((*MockStorage)(nil).SaveNewKeyPair), arg0)
}

// TerminateSession mocks base method
func (m *MockStorage) TerminateSession(arg0 context.Context, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TerminateSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// TerminateSession indicates an expected call of TerminateSession
func (mr *MockStorageMockRecorder) TerminateSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TerminateSession", reflect.TypeOf((*MockStorage)(nil).TerminateSession), arg0, arg1, arg2)
}

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/authelia/authelia/v4/internal/duo (interfaces: API)

// Package mocks is a generated GoMock package.
package mocks

import (
	url "net/url"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"

	duo "github.com/authelia/authelia/v4/internal/duo"
	middlewares "github.com/authelia/authelia/v4/internal/middlewares"
)

// MockAPI is a mock of API interface.
type MockAPI struct {
	ctrl     *gomock.Controller
	recorder *MockAPIMockRecorder
}

// MockAPIMockRecorder is the mock recorder for MockAPI.
type MockAPIMockRecorder struct {
	mock *MockAPI
}

// NewMockAPI creates a new mock instance.
func NewMockAPI(ctrl *gomock.Controller) *MockAPI {
	mock := &MockAPI{ctrl: ctrl}
	mock.recorder = &MockAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAPI) EXPECT() *MockAPIMockRecorder {
	return m.recorder
}

// AuthCall mocks base method.
func (m *MockAPI) AuthCall(arg0 *middlewares.AutheliaCtx, arg1 url.Values) (*duo.AuthResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthCall", arg0, arg1)
	ret0, _ := ret[0].(*duo.AuthResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthCall indicates an expected call of AuthCall.
func (mr *MockAPIMockRecorder) AuthCall(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthCall", reflect.TypeOf((*MockAPI)(nil).AuthCall), arg0, arg1)
}

// Call mocks base method.
func (m *MockAPI) Call(arg0 *middlewares.AutheliaCtx, arg1 url.Values, arg2, arg3 string) (*duo.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Call", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*duo.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Call indicates an expected call of Call.
func (mr *MockAPIMockRecorder) Call(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Call", reflect.TypeOf((*MockAPI)(nil).Call), arg0, arg1, arg2, arg3)
}

// PreAuthCall mocks base method.
func (m *MockAPI) PreAuthCall(arg0 *middlewares.AutheliaCtx, arg1 url.Values) (*duo.PreAuthResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PreAuthCall", arg0, arg1)
	ret0, _ := ret[0].(*duo.PreAuthResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PreAuthCall indicates an expected call of PreAuthCall.
func (mr *MockAPIMockRecorder) PreAuthCall(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PreAuthCall", reflect.TypeOf((*MockAPI)(nil).PreAuthCall), arg0, arg1)
}
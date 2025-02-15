// Code generated by MockGen. DO NOT EDIT.
// Source: client.go

// Package http is a generated GoMock package.
package http

import (
	io "io"
	http "net/http"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockClient is a mock of Client interface.
type MockClient[R interface{}] struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder[R]
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder[R interface{}] struct {
	mock *MockClient[R]
}

// NewMockClient creates a new mock instance.
func NewMockClient[R interface{}](ctrl *gomock.Controller) *MockClient[R] {
	mock := &MockClient[R]{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder[R]{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient[R]) EXPECT() *MockClientMockRecorder[R] {
	return m.recorder
}

// Do mocks base method.
func (m *MockClient[R]) Do(req *http.Request) (*http.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Do", req)
	ret0, _ := ret[0].(*http.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Do indicates an expected call of Do.
func (mr *MockClientMockRecorder[R]) Do(req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Do", reflect.TypeOf((*MockClient[R])(nil).Do), req)
}

// NewRequest mocks base method.
func (m *MockClient[R]) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewRequest", method, url, body)
	ret0, _ := ret[0].(*http.Request)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewRequest indicates an expected call of NewRequest.
func (mr *MockClientMockRecorder[R]) NewRequest(method, url, body interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewRequest", reflect.TypeOf((*MockClient[R])(nil).NewRequest), method, url, body)
}

// Send mocks base method.
func (m *MockClient[R]) Send(request Request) (Result[R], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Send", request)
	ret0, _ := ret[0].(Result[R])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Send indicates an expected call of Send.
func (mr *MockClientMockRecorder[R]) Send(request interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockClient[R])(nil).Send), request)
}

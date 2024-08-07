// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/wuxler/ruasec/pkg/ocispec (interfaces: Manifest,IndexManifest)
//
// Generated by this command:
//
//	mockgen -destination=./mocks/mock_manifest.go -package=mocks github.com/wuxler/ruasec/pkg/ocispec Manifest,IndexManifest
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	gomock "go.uber.org/mock/gomock"
)

// MockManifest is a mock of Manifest interface.
type MockManifest struct {
	ctrl     *gomock.Controller
	recorder *MockManifestMockRecorder
}

// MockManifestMockRecorder is the mock recorder for MockManifest.
type MockManifestMockRecorder struct {
	mock *MockManifest
}

// NewMockManifest creates a new mock instance.
func NewMockManifest(ctrl *gomock.Controller) *MockManifest {
	mock := &MockManifest{ctrl: ctrl}
	mock.recorder = &MockManifestMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManifest) EXPECT() *MockManifestMockRecorder {
	return m.recorder
}

// MediaType mocks base method.
func (m *MockManifest) MediaType() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MediaType")
	ret0, _ := ret[0].(string)
	return ret0
}

// MediaType indicates an expected call of MediaType.
func (mr *MockManifestMockRecorder) MediaType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MediaType", reflect.TypeOf((*MockManifest)(nil).MediaType))
}

// Payload mocks base method.
func (m *MockManifest) Payload() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Payload")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Payload indicates an expected call of Payload.
func (mr *MockManifestMockRecorder) Payload() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Payload", reflect.TypeOf((*MockManifest)(nil).Payload))
}

// References mocks base method.
func (m *MockManifest) References() []v1.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "References")
	ret0, _ := ret[0].([]v1.Descriptor)
	return ret0
}

// References indicates an expected call of References.
func (mr *MockManifestMockRecorder) References() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "References", reflect.TypeOf((*MockManifest)(nil).References))
}

// MockIndexManifest is a mock of IndexManifest interface.
type MockIndexManifest struct {
	ctrl     *gomock.Controller
	recorder *MockIndexManifestMockRecorder
}

// MockIndexManifestMockRecorder is the mock recorder for MockIndexManifest.
type MockIndexManifestMockRecorder struct {
	mock *MockIndexManifest
}

// NewMockIndexManifest creates a new mock instance.
func NewMockIndexManifest(ctrl *gomock.Controller) *MockIndexManifest {
	mock := &MockIndexManifest{ctrl: ctrl}
	mock.recorder = &MockIndexManifestMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIndexManifest) EXPECT() *MockIndexManifestMockRecorder {
	return m.recorder
}

// Manifests mocks base method.
func (m *MockIndexManifest) Manifests() []v1.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Manifests")
	ret0, _ := ret[0].([]v1.Descriptor)
	return ret0
}

// Manifests indicates an expected call of Manifests.
func (mr *MockIndexManifestMockRecorder) Manifests() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Manifests", reflect.TypeOf((*MockIndexManifest)(nil).Manifests))
}

// MediaType mocks base method.
func (m *MockIndexManifest) MediaType() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MediaType")
	ret0, _ := ret[0].(string)
	return ret0
}

// MediaType indicates an expected call of MediaType.
func (mr *MockIndexManifestMockRecorder) MediaType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MediaType", reflect.TypeOf((*MockIndexManifest)(nil).MediaType))
}

// Payload mocks base method.
func (m *MockIndexManifest) Payload() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Payload")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Payload indicates an expected call of Payload.
func (mr *MockIndexManifestMockRecorder) Payload() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Payload", reflect.TypeOf((*MockIndexManifest)(nil).Payload))
}

// References mocks base method.
func (m *MockIndexManifest) References() []v1.Descriptor {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "References")
	ret0, _ := ret[0].([]v1.Descriptor)
	return ret0
}

// References indicates an expected call of References.
func (mr *MockIndexManifestMockRecorder) References() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "References", reflect.TypeOf((*MockIndexManifest)(nil).References))
}

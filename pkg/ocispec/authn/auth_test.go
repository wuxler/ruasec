package authn_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

func newExampleRequest(t *testing.T) *http.Request {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", http.NoBody)
	require.NoError(t, err)
	return req
}

func TestAuthorizerFunc(t *testing.T) {
	want := "Bearer token"
	var auth authn.AuthorizeFunc = func(req *http.Request) error {
		req.Header.Set("Authorization", want)
		return nil
	}
	req := newExampleRequest(t)
	err := auth.Authorize(req)
	require.NoError(t, err)
	got := req.Header.Get("Authorization")
	assert.Equal(t, want, got)
}

func TestAnonymous(t *testing.T) {
	auth := authn.NewAnonymous()
	req := newExampleRequest(t)
	err := auth.Authorize(req)
	require.NoError(t, err)
	got := req.Header.Get("Authorization")
	assert.Empty(t, got)
}

func TestBasic(t *testing.T) {
	testcases := []struct {
		name     string
		username string
		password string
		want     string
	}{
		{
			name:     "basic",
			username: "foo",
			password: "bar",
			want:     "Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar")),
		},
		{
			name:     "empty password",
			username: "foo",
		},
		{
			name:     "empty username",
			password: "bar",
		},
		{
			name: "empty username and password",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			auth := authn.NewBasic(tc.username, tc.password)
			req := newExampleRequest(t)
			err := auth.Authorize(req)
			require.NoError(t, err)
			got := req.Header.Get("Authorization")
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestToken(t *testing.T) {
	testcases := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "bearer token",
			value: "token-value",
			want:  "Bearer token-value",
		},
		{
			name: "empty token",
			want: "",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			auth := authn.NewToken(tc.value)
			req := newExampleRequest(t)
			err := auth.Authorize(req)
			require.NoError(t, err)
			got := req.Header.Get("Authorization")
			assert.Equal(t, tc.want, got)
		})
	}
}

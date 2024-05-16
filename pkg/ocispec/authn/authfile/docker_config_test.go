package authfile

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

func TestDockerConfigFile_Erase(t *testing.T) {
	content := ` { "auths": { "https://index.docker.io/v1/": { "auth": "am9lam9lOmhlbGxv" } } }`

	cfg := NewDockerConfigFile()
	err := json.Unmarshal([]byte(content), cfg)
	require.NoError(t, err)

	err = cfg.Erase(context.Background(), "https://index.docker.io/v1/")
	require.NoError(t, err)
	buf := &bytes.Buffer{}
	err = cfg.SaveToWriter(buf)
	require.NoError(t, err)

	want := `{"auths": {}}`
	assert.JSONEq(t, want, buf.String())
}

func TestDockerConfigFile_Get(t *testing.T) {
	content := ` { "auths": { "https://index.docker.io/v1/": { "auth": "am9lam9lOmhlbGxv" } } }`

	cfg := NewDockerConfigFile()
	err := json.Unmarshal([]byte(content), cfg)
	require.NoError(t, err)

	t.Run("exist", func(t *testing.T) {
		got, err := cfg.Get(context.Background(), "https://index.docker.io/v1/")
		require.NoError(t, err)
		want := authn.AuthConfig{
			Username: "joejoe",
			Password: "hello",
			Auth:     "am9lam9lOmhlbGxv",
		}
		assert.Equal(t, want, got)
	})

	t.Run("not exist", func(t *testing.T) {
		got, err := cfg.Get(context.Background(), "registry.example.com")
		require.NoError(t, err)
		want := authn.EmptyAuthConfig
		assert.Equal(t, want, got)
	})
}

func TestDockerConfigFile_GetAll(t *testing.T) {
	cfg := NewDockerConfigFile()
	content := ` { "auths": { "https://index.docker.io/v1/": { "auth": "am9lam9lOmhlbGxv" } } }`
	err := json.Unmarshal([]byte(content), cfg)
	require.NoError(t, err)

	all, err := cfg.GetAll(context.Background())
	require.NoError(t, err)

	// change returned auth map and check no effect to raw config
	all["registry.example.com"] = authn.AuthConfig{Username: "admin", Password: "hello"}

	buf := &bytes.Buffer{}
	err = cfg.SaveToWriter(buf)
	require.NoError(t, err)
	assert.JSONEq(t, content, buf.String())
}

func TestDockerConfigFile_Store(t *testing.T) {
	cfg := NewDockerConfigFile()
	buf := &bytes.Buffer{}
	err := cfg.SaveToWriter(buf)
	require.NoError(t, err)

	assert.JSONEq(t, `{"auths": {}}`, buf.String())

	ctx := context.Background()
	err = cfg.Store(ctx, "https://index.docker.io/v1/", authn.AuthConfig{
		Username: "joejoe",
		Password: "hello",
	})
	require.NoError(t, err)
	buf.Reset()
	err = cfg.SaveToWriter(buf)
	require.NoError(t, err)
	assert.JSONEq(t, `{"auths": {"https://index.docker.io/v1/": {"auth": "am9lam9lOmhlbGxv"}}}`, buf.String())

	err = cfg.Store(ctx, "registry.example.com", authn.AuthConfig{
		Username: "abc:abc",
		Password: "hello",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "colons(:) are not allowed in username")
}

func TestDockerConfigFile_ContainsAuth(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		cfg := NewDockerConfigFile()
		got := cfg.ContainsAuth()
		assert.False(t, got)
	})
	t.Run("no empty auth", func(t *testing.T) {
		cfg := NewDockerConfigFile()
		err := cfg.Store(context.Background(), "https://index.docker.io/v1/", authn.AuthConfig{
			Username: "joejoe",
			Password: "hello",
		})
		require.NoError(t, err)
		got := cfg.ContainsAuth()
		assert.True(t, got)
	})
	t.Run("no empty credentials store", func(t *testing.T) {
		cfg := NewDockerConfigFile()
		cfg.CredentialsStore = "cracy-secure-storage"
		got := cfg.ContainsAuth()
		assert.True(t, got)
	})

	t.Run("no empty credential helpers", func(t *testing.T) {
		cfg := NewDockerConfigFile()
		cfg.CredentialHelpers = map[string]string{
			"images.io": "images-io",
		}
		got := cfg.ContainsAuth()
		assert.True(t, got)
	})
}

package authfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

func TestAuthFile_Load(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "authfile.json")
		err := NewAuthFile(filename).Load()
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("empty file", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "authfile.json")
		err := os.WriteFile(filename, []byte(""), 0o600)
		require.NoError(t, err)
		err = NewAuthFile(filename).Load()
		assert.NoError(t, err)
	})

	t.Run("empty json", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "authfile.json")
		err := os.WriteFile(filename, []byte("{}"), 0o600)
		require.NoError(t, err)
		err = NewAuthFile(filename).Load()
		assert.NoError(t, err)
	})
}

func TestAuthFileGetCredentialStore(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.json")
	assert.NoFileExists(t, filename)

	authFile := NewAuthFile(filename)
	store := authFile.GetCredentialsStore()
	err := store.Store(context.Background(), "registry.example.com", authn.AuthConfig{
		Username: "admin",
		Password: "hello",
	})
	require.NoError(t, err)
	assert.FileExists(t, filename)
}

func TestPlainTextLegacyAuthFile(t *testing.T) {
	testcases := []struct {
		name    string
		content string
		want    string
		wantErr string
	}{
		{
			name: "valid file",
			content: `username = am9lam9lOmhlbGxv
email = user@example.com`,
			want: `{
    "auths": {
        "https://index.docker.io/v1/": {
            "auth": "am9lam9lOmhlbGxv"
        }
    }
}`,
		},
		{
			name:    "invalid as empty",
			content: "username = test",
			wantErr: "the legacy auth config is empty",
		},
		{
			name: "invalid file format",
			content: `username
password`,
			wantErr: "invalid legacy auth config file",
		},
		{
			name: "invalid auth format",
			content: `username = test
email`,
			wantErr: "invalid auth, base64 as format 'username:password' is required",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "legacy-authfile.json")
			err := os.WriteFile(filename, []byte(tc.content), 0o600)
			require.NoError(t, err)
			authFile := NewLegacyAuthFile(filename)
			err = authFile.Load()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			err = authFile.Save(context.Background())
			require.NoError(t, err)

			data, err := os.ReadFile(filename)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(data))
		})
	}
}

func TestJSONLegacyAuthFile(t *testing.T) {
	testcases := []struct {
		name    string
		content string
		want    string
		wantErr string
	}{
		{
			name:    "valid",
			content: `{"https://index.docker.io/v1/":{"auth":"am9lam9lOmhlbGxv","email":"user@example.com"}}`,
			want: `{
    "auths": {
        "https://index.docker.io/v1/": {
            "auth": "am9lam9lOmhlbGxv"
        }
    }
}`,
		},
		{
			name:    "invalid",
			content: `{"https://index.docker.io/v1/":{"auth":"test","email":"user@example.com"}}`,
			wantErr: "invalid auth",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "legacy-authfile.json")
			err := os.WriteFile(filename, []byte(tc.content), 0o600)
			require.NoError(t, err)
			authFile := NewLegacyAuthFile(filename)
			err = authFile.Load()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			err = authFile.Save(context.Background())
			require.NoError(t, err)
			data, err := os.ReadFile(filename)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(data))
		})
	}
}

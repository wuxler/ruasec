package remote

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/ocispec/authn/authfile"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// AuthProvider provides the AuthConfig related to the registry.
type AuthProvider func(ctx context.Context, host string) authn.AuthConfig

// NewAuthProviderFromAuthFile returns an AuthProvider with the *authfile.AuthFile provided.
func NewAuthProviderFromAuthFile(authFile *authfile.AuthFile) AuthProvider {
	return func(ctx context.Context, host string) authn.AuthConfig {
		authConfig, err := authFile.Get(ctx, host)
		if err != nil {
			xlog.C(ctx).Warnf("failed to get auth config for host %s: %v", host, err)
		}
		return authConfig
	}
}

// NewAuthProviderFromAuthFilePath returns an AuthProvider with the auth file path provided.
// It will ignore the file load error when the path is not existed.
func NewAuthProviderFromAuthFilePath(path string) (AuthProvider, error) {
	authFile := authfile.NewAuthFile(path)
	if err := authFile.Load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to load auth file: %w", err)
		}
	}
	return NewAuthProviderFromAuthFile(authFile), nil
}

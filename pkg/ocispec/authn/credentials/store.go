package credentials

import (
	"context"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

// Store is the interface that any credentials store must implement.
type Store interface {
	// Erase removes credentials from the store for a given server.
	Erase(ctx context.Context, host string) error
	// Get retrieves credentials from the store for a given server.
	Get(ctx context.Context, host string) (authn.AuthConfig, error)
	// GetAll retrieves all the credentials from the store.
	GetAll(ctx context.Context) (map[string]authn.AuthConfig, error)
	// Store saves credentials in the store.
	Store(ctx context.Context, host string, authConfig authn.AuthConfig) error
}

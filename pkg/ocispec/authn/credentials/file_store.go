package credentials

import (
	"context"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

type fileStoreAdapter interface {
	Store
	Save(ctx context.Context) error
}

// NewFileStore creates a new file credentials store.
func NewFileStore(file fileStoreAdapter) Store {
	return &fileStore{file: file}
}

// fileStore implements a credentials store using
// the docker configuration file to keep the credentials in plain text.
type fileStore struct {
	file fileStoreAdapter
}

// Erase removes credentials from the store for a given server.
func (s *fileStore) Erase(ctx context.Context, host string) error {
	if err := s.file.Erase(ctx, host); err != nil {
		return err
	}
	return s.file.Save(ctx)
}

// Get retrieves credentials from the store for a given server.
func (s *fileStore) Get(ctx context.Context, host string) (authn.AuthConfig, error) {
	return s.file.Get(ctx, host)
}

// GetAll retrieves all the credentials from the store.
func (s *fileStore) GetAll(ctx context.Context) (map[string]authn.AuthConfig, error) {
	return s.file.GetAll(ctx)
}

// Store saves credentials in the store.
func (s *fileStore) Store(ctx context.Context, host string, authConfig authn.AuthConfig) error {
	if err := s.file.Store(ctx, host, authConfig); err != nil {
		return err
	}
	return s.file.Save(ctx)
}

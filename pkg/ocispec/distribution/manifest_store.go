package distribution

import (
	"context"
	"errors"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// ManifestStore is a storage interface for manifests resource.
type ManifestStore interface {
	cas.Storage
	// FetchTagOrDigest fetches the content for the given tag or digest.
	FetchTagOrDigest(ctx context.Context, tagOrDigest string) (cas.ReadCloser, error)
}

// NewManifestStore returns a [ManifestStore] with the given distribution Spec
// and repository path formatted as "library/alpine".
func NewManifestStore(spec Spec, repo string) ManifestStore {
	return &manifestStore{spec: spec, repo: repo}
}

type manifestStore struct {
	spec Spec
	repo string
}

// FetchTagOrDigest fetches the content for the given tag or digest.
func (s *manifestStore) FetchTagOrDigest(ctx context.Context, tagOrDigest string) (cas.ReadCloser, error) {
	return s.spec.GetManifest(ctx, s.repo, tagOrDigest)
}

// Stat returns the descriptor for the given reference.
func (s *manifestStore) Stat(ctx context.Context, reference string) (imgspecv1.Descriptor, error) {
	return s.spec.StatManifest(ctx, s.repo, reference)
}

// Exists returns true if the described content exists.
func (s *manifestStore) Exists(ctx context.Context, target imgspecv1.Descriptor) (bool, error) {
	_, err := s.Stat(ctx, target.Digest.String())
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errdefs.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// Fetch fetches the content identified by the descriptor.
func (s *manifestStore) Fetch(ctx context.Context, target imgspecv1.Descriptor) (cas.ReadCloser, error) {
	return s.FetchTagOrDigest(ctx, target.Digest.String())
}

// Push pushes the content got by the given getter.
func (s *manifestStore) Push(ctx context.Context, getter cas.ReadCloserGetter) error {
	rc, err := getter(ctx)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)
	return s.spec.PushManifest(ctx, s.repo, rc)
}

// Delete removes the content identified by the descriptor.
func (s *manifestStore) Delete(ctx context.Context, target imgspecv1.Descriptor) error {
	return s.spec.DeleteManifest(ctx, s.repo, target.Digest.String())
}

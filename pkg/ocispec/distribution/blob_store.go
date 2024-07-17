package distribution

import (
	"context"
	"errors"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
)

// BlobStore is a storage interface for blobs resource.
type BlobStore interface {
	cas.Storage
}

// NewBlobStore returns a [BlobStore] with the given distribution Spec
// and repository path formatted as "library/alpine".
func NewBlobStore(spec Spec, repo string) BlobStore {
	return &blobStore{spec: spec, repo: repo}
}

type blobStore struct {
	spec Spec
	repo string
}

// Stat returns the descriptor for the given reference.
func (s *blobStore) Stat(ctx context.Context, reference string) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	dgst, err := digest.Parse(reference)
	if err != nil {
		return zero, err
	}
	return s.spec.StatBlob(ctx, s.repo, dgst)
}

// Exists returns true if the described content exists.
func (s *blobStore) Exists(ctx context.Context, target imgspecv1.Descriptor) (bool, error) {
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
func (s *blobStore) Fetch(ctx context.Context, target imgspecv1.Descriptor) (cas.ReadCloser, error) {
	return s.spec.GetBlob(ctx, s.repo, target.Digest)
}

// Push pushes the content [Reader].
func (s *blobStore) Push(ctx context.Context, content cas.Reader) error {
	panic("not implemented") // TODO: Implement
}

// Delete removes the content identified by the descriptor.
func (s *blobStore) Delete(ctx context.Context, target imgspecv1.Descriptor) error {
	return s.spec.DeleteBlob(ctx, s.repo, target.Digest)
}

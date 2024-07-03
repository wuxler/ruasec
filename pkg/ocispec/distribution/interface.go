package distribution

import (
	"context"
	"errors"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/name"
)

var (
	// ErrIteratorDone indicates the iterator is complete.
	ErrIteratorDone = errors.New("iterator done")
)

// Registry is the interface for a distribution registry.
type Registry interface {
	// Named returns the name of the registry.
	Named() name.Registry

	// Ping checks registry is accessible.
	Ping(ctx context.Context) error

	// Repository returns the [Repository] by the given path which is the repository name.
	Repository(ctx context.Context, path string) (Repository, error)

	// ListRepositories lists the repositories.
	ListRepositories(options ...ListOption) Iterator[Repository]
}

// Namespaced is the interface for a distibution registry who supports top-level namespace/project/organization
// operations.
type Namespaced interface {
	// ListNamespaces lists the namespaces.
	ListNamespaces(ctx context.Context, options ...ListOption) (Iterator[string], error)
	// Namespace returns a [Repository] by the given namespace wrapped.
	Namespace(ctx context.Context, ns string) Repository
}

// Repository is the interface for a distribution repository.
type Repository interface {
	// Named returns the name of the repository.
	Named() name.Repository
	// Manifests returns a reference to this repository's manifest storage.
	Manifests() ManifestStore
	// Tags returns a reference to this repository's tag storage.
	Tags() TagStore
	// Blobs returns a reference to this repository's blob storage.
	Blobs() BlobStore
}

// BlobStore is a storage interface for blobs resource.
type BlobStore interface {
	cas.Storage
}

// ManifestStore is a storage interface for manifests resource.
type ManifestStore interface {
	cas.Storage
	// FetchTagOrDigest fetches the content for the given tag or digest.
	FetchTagOrDigest(ctx context.Context, tagOrDigest string) (cas.ReadCloser, error)
	// StatTagOrDigest returns the descriptor for the given tag or digest.
	StatTagOrDigest(ctx context.Context, tagOrDigest string) (imgspecv1.Descriptor, error)
}

// TagStore is a storage interface for tags resource.
type TagStore interface {
	// Stat retrieves the descriptor identified by the given tag.
	Stat(ctx context.Context, tag string) (imgspecv1.Descriptor, error)
	// Tag tags the target by the given tag.
	Tag(ctx context.Context, target cas.Reader, tag string) error
	// Untag removes the tag.
	Untag(ctx context.Context, tag string) error
	// List lists the tags.
	List(options ...ListOption) Iterator[string]
}

var _ Iterator[string] = IteratorFunc[string](nil)

// Iterator is the interface for list operation.
type Iterator[T any] interface {
	// Next called for next page. If no more items to iterate, returns error with [ErrIteratorDone].
	Next(ctx context.Context) ([]T, error)
}

// IteratorFunc is a function that implements [Iterator].
type IteratorFunc[T any] func(context.Context) ([]T, error)

// Next called for next page.
func (fn IteratorFunc[T]) Next(ctx context.Context) ([]T, error) {
	return fn(ctx)
}

// ListOption used as optional parameters in list function.
type ListOption func(*ListOptions)

// ListOptions is the options of the list operations.
type ListOptions struct {
	// PageSize represents each iterate page size.
	PageSize int
	// Offset represents where the list iterator should start at.
	Offset string
}

// WithPageSize sets the page size option.
func WithPageSize(size int) ListOption {
	return func(o *ListOptions) {
		o.PageSize = size
	}
}

// WithOffset sets the offset option.
func WithOffset(offset string) ListOption {
	return func(o *ListOptions) {
		o.Offset = offset
	}
}

// MakeListOptions returns the list options with all optional parameters applied.
func MakeListOptions(opts ...ListOption) *ListOptions {
	var options ListOptions
	for _, opt := range opts {
		opt(&options)
	}
	return &options
}

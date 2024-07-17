package registry

import (
	"context"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	"github.com/wuxler/ruasec/pkg/ocispec/iter"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

// Registry is the interface for a distribution registry.
type Registry interface {
	// Name returns the name of the registry.
	Name() ocispecname.Registry

	// Ping checks registry is accessible.
	Ping(ctx context.Context) error

	// Repository returns the [Repository] by the given path which is the repository name.
	Repository(path string) (Repository, error)

	// ListRepositories lists the repositories.
	ListRepositories(options ...distribution.ListOption) iter.Iterator[Repository]
}

// Repository is the interface for a distribution repository.
type Repository interface {
	// Name returns the name of the repository.
	Name() ocispecname.Repository
	// Registry returns the registry of the repository.
	Registry() Registry
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
	List(options ...distribution.ListOption) iter.Iterator[string]
}

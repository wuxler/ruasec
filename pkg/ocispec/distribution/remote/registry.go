package remote

import (
	"context"

	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	"github.com/wuxler/ruasec/pkg/ocispec/iter"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

func NewRegistry(ctx context.Context, name ocispecname.Registry, opts ...Option) (*Registry, error) {
	spec, err := NewSpec(ctx, name, opts...)
	if err != nil {
		return nil, err
	}
	return &Registry{spec}, nil
}

type Registry struct {
	spec *Spec
}

// Name returns the name of the registry.
func (r *Registry) Name() ocispecname.Registry {
	return r.spec.name
}

// Ping checks registry is accessible.
func (r *Registry) Ping(ctx context.Context) error {
	_, err := r.spec.GetVersion(ctx)
	return err
}

// Repository returns the [Repository] by the given path which is the repository name.
//
// NOTE: Invalid "path" will cause panic.
func (r *Registry) Repository(path string) *Repository {
	return &Repository{
		registry: r,
		name:     ocispecname.MustWithPath(r.Name(), path),
	}
}

// ListRepositories lists the repositories.
func (r *Registry) ListRepositories(opts ...distribution.ListOption) iter.Iterator[*Repository] {
	iterator := r.spec.ListRepositories(opts...)
	return iter.IteratorFunc[*Repository](func(ctx context.Context) ([]*Repository, error) {
		paths, err := iterator.Next(ctx)
		if err != nil {
			return nil, err
		}
		repos := []*Repository{}
		for _, repoPath := range paths {
			repos = append(repos, r.Repository(repoPath))
		}
		return repos, nil
	})
}

func NewRepository(ctx context.Context, name ocispecname.Repository, opts ...Option) (*Repository, error) {
	registry, err := NewRegistry(ctx, name.Domain(), opts...)
	if err != nil {
		return nil, err
	}
	return registry.Repository(name.Path()), nil
}

type Repository struct {
	registry *Registry
	name     ocispecname.Repository
}

// Name returns the name of the repository.
func (r *Repository) Name() ocispecname.Repository {
	return r.name
}

// Registry returns the registry of the repository.
func (r *Repository) Registry() *Registry {
	return r.registry
}

// Manifests returns a reference to this repository's manifest storage.
func (r *Repository) Manifests() distribution.ManifestStore {
	return distribution.NewManifestStore(r.registry.spec, r.Name().Path())
}

// Tags returns a reference to this repository's tag storage.
func (r *Repository) Tags() distribution.TagStore {
	return distribution.NewTagStore(r.registry.spec, r.Name().Path())
}

// Blobs returns a reference to this repository's blob storage.
func (r *Repository) Blobs() distribution.BlobStore {
	return distribution.NewBlobStore(r.registry.spec, r.Name().Path())
}

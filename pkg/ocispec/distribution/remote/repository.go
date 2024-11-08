package remote

import (
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

// Repository provides access to a remote repository.
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
	return distribution.NewManifestStore(r.registry, r.Name().Path())
}

// Tags returns a reference to this repository's tag storage.
func (r *Repository) Tags() distribution.TagStore {
	return distribution.NewTagStore(r.registry, r.Name().Path())
}

// Blobs returns a reference to this repository's blob storage.
func (r *Repository) Blobs() distribution.BlobStore {
	return distribution.NewBlobStore(r.registry, r.Name().Path())
}

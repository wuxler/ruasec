// Package cas provides CAS (Content Addressable Storage) implementations.
package cas

import (
	"context"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Describable defines a resource that can be described.
type Describable interface {
	// Descriptor returns the descriptor for the resource.
	Descriptor() imgspecv1.Descriptor
}

type Storage interface {
	// Stat returns the descriptor for the given reference.
	Stat(ctx context.Context, reference string) (imgspecv1.Descriptor, error)
	// Exists returns true if the described content exists.
	Exists(ctx context.Context, target imgspecv1.Descriptor) (bool, error)
	// Fetch fetches the content identified by the descriptor.
	Fetch(ctx context.Context, target imgspecv1.Descriptor) (ReadCloser, error)
	// Push pushes the content [Reader].
	Push(ctx context.Context, content Reader) error
	// Delete removes the content identified by the descriptor.
	Delete(ctx context.Context, target imgspecv1.Descriptor) error
}

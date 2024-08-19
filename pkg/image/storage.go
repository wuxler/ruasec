package image

import (
	"context"

	"github.com/wuxler/ruasec/pkg/ocispec"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

// Storage is the common interface for image backend storages. It must be implemented by
// all image backends.
type Storage interface {
	// Type returns the unique identity type of the provider.
	Type() string
	Getter
}

// Getter is the interface for image getter.
type Getter interface {
	// GetImage returns the image specified by ref.
	//
	// NOTE: The image must be closed when processing is finished.
	GetImage(ctx context.Context, ref ocispecname.Reference, opts ...ImageOption) (ocispec.ImageCloser, error)
}

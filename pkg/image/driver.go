package image

import (
	"context"

	"github.com/wuxler/ruasec/pkg/ocispec"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

// Driver is the common interface for image backend storages. It must be implemented by
// all image backends.
type Driver interface {
	// Name returns the unique identity name of the provider.
	Name() string
	Getter
}

// Getter is the interface for image getter.
type Getter interface {
	// GetImage returns the image specified by ref.
	//
	// NOTE: The image must be closed when processing is finished.
	GetImage(ctx context.Context, ref ocispecname.Reference, opts ...ImageOption) (ocispec.ImageCloser, error)
}

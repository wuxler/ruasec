package image

import (
	"context"

	"github.com/wuxler/ruasec/pkg/ocispec"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

// NewImageFromString returns the image specified by string name with the given driver.
func NewImageFromString(ctx context.Context, storage Storage, name string, opts ...ImageOption) (ocispec.ImageCloser, error) {
	ref, err := ocispecname.NewReference(name)
	if err != nil {
		return nil, err
	}
	opts = append(opts, WithMetadataApplier(func(metadata *ocispec.ImageMetadata) {
		// override metadata name with raw input
		metadata.Name = name
	}))
	return storage.GetImage(ctx, ref, opts...)
}

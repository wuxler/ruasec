package image

import (
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

// ImageOption is the optional parameter setting method.
type ImageOption func(*ImageOptions)

// WithPlatform sets the platform of the target image when the ref contains multiple
// instances.
func WithPlatform(platform *imgspecv1.Platform) ImageOption {
	return func(o *ImageOptions) {
		o.Platform = platform
	}
}

// WithImageID sets the instance digest of the target image when the ref contains multiple
// instances.
func WithInstanceDigest(dgst digest.Digest) ImageOption {
	return func(o *ImageOptions) {
		o.InstanceDigest = dgst
	}
}

// WithMetadataApplier appends the metadata applier to the list of metadata appliers to
// modify image metadata from caller.
func WithMetadataApplier(applier func(*ocispec.ImageMetadata)) ImageOption {
	return func(o *ImageOptions) {
		if applier != nil {
			o.MetadataAppliers = append(o.MetadataAppliers, applier)
		}
	}
}

// ImageOptions is the structure of the optional parameters.
type ImageOptions struct {
	Platform         *imgspecv1.Platform
	InstanceDigest   digest.Digest
	MetadataAppliers []func(*ocispec.ImageMetadata)
}

// ApplyMetadata applies the metadata appliers to the image metadata.
func (o *ImageOptions) ApplyMetadata(metadata *ocispec.ImageMetadata) {
	for _, applier := range o.MetadataAppliers {
		applier(metadata)
	}
}

// DescriptorMatchers returns the list of descriptor matchers to use when resolving the image.
func (o *ImageOptions) DescriptorMatchers() []manifest.DescriptorMatcher {
	return []manifest.DescriptorMatcher{
		manifest.DescriptorMatcherByDigest(o.InstanceDigest),
		manifest.DescriptorMatcherByPlatform(o.Platform),
	}
}

// MakeImageOptions returns the options with all optional parameters applied.
func MakeImageOptions(opts ...ImageOption) *ImageOptions {
	options := &ImageOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return options
}

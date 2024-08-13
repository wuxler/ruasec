package manifest

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// ManifestFetcher is an interface for fetching manifests from a storage.
type ManifestFetcher interface {
	// Fetch fetches the content for the given descriptor.
	Fetch(ctx context.Context, desc imgspecv1.Descriptor) (cas.ReadCloser, error)
}

// DescriptorMatcher is a function that selects a descriptor from a list of descriptors.
type DescriptorMatcher func(descs ...imgspecv1.Descriptor) (imgspecv1.Descriptor, bool)

// SelectImageManifest selects the single image manifest from the given src manifest.
// If the src is an image manifest, it is returned as is.
// If the src is an index manifest, the image manifest matching the given matchers is returned.
func SelectImageManifest(ctx context.Context, fetcher ManifestFetcher, src ocispec.Manifest, srcDesc imgspecv1.Descriptor, matchers ...DescriptorMatcher) (ImageManifest, imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor

	switch mf := src.(type) {
	case ImageManifest:
		return mf, srcDesc, nil
	case ocispec.IndexManifest:
		selectedManifest, selectedDesc, err := SelectManifest(ctx, fetcher, mf, matchers...)
		if err != nil {
			return nil, zero, err
		}
		imf, ok := selectedManifest.(ImageManifest)
		if !ok {
			return nil, zero, fmt.Errorf("unexpected manifest type %T", selectedManifest)
		}
		return imf, selectedDesc, nil
	default:
		return nil, zero, errdefs.Newf(errdefs.ErrUnsupported, "unsupported manifest type %T", src)
	}
}

// SelectManifest selects the target manifest from the given index manifest.
func SelectManifest(ctx context.Context, fetcher ManifestFetcher, index ocispec.IndexManifest, matchers ...DescriptorMatcher) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	descriptors := index.Manifests()
	if len(descriptors) == 0 {
		return nil, zero, errors.New("index manifest has no manifests")
	}

	var desc imgspecv1.Descriptor
	found := false
	for _, matcher := range matchers {
		desc, found = matcher(descriptors...)
		if found {
			break
		}
	}
	if !found {
		return nil, zero, errdefs.Newf(errdefs.ErrNotFound, "no manifest selected with descriptor matchers")
	}

	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, zero, err
	}
	defer xio.CloseAndSkipError(rc)

	parsed, _, err := ParseCASReader(rc)
	if err != nil {
		return nil, zero, err
	}
	return parsed, desc, nil
}

// DescriptorMatcherByDigest returns a DescriptorMatcher that selects a descriptor by the dgst applied.
func DescriptorMatcherByDigest(dgst digest.Digest) DescriptorMatcher {
	return func(descs ...imgspecv1.Descriptor) (imgspecv1.Descriptor, bool) {
		return lo.Find(descs, func(desc imgspecv1.Descriptor) bool {
			if dgst == "" {
				return false
			}
			return desc.Digest == dgst
		})
	}
}

// DescriptorMatcherByPlatform returns a DescriptorMatcher that selects a descriptor by the platform applied.
func DescriptorMatcherByPlatform(target *imgspecv1.Platform) DescriptorMatcher {
	p := platforms.DefaultSpec()
	if target != nil {
		p = *target
	}
	matcher := platforms.OnlyStrict(p)
	return func(descs ...imgspecv1.Descriptor) (imgspecv1.Descriptor, bool) {
		return lo.Find(descs, func(desc imgspecv1.Descriptor) bool {
			if desc.Platform == nil {
				return false
			}
			return matcher.Match(*desc.Platform)
		})
	}
}

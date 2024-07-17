package manifest

import (
	"context"
	"errors"

	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// ManifestFetcher is an interface for fetching manifests from a storage.
type ManifestFetcher interface {
	// Fetch fetches the content for the given descriptor.
	Fetch(ctx context.Context, desc imgspecv1.Descriptor) (cas.ReadCloser, error)
}

// DescriptorMatcher is a function that selects a descriptor from a list of descriptors.
type DescriptorMatcher func(descs ...imgspecv1.Descriptor) (imgspecv1.Descriptor, error)

// SelectManifest selects the target manifest from the given index manifest.
func SelectManifest(ctx context.Context, fetcher ManifestFetcher, index ocispec.IndexManifest, matchers ...DescriptorMatcher) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	descriptors := index.Manifests()
	if len(descriptors) == 0 {
		return nil, zero, errors.New("index manifest has no manifests")
	}

	var desc imgspecv1.Descriptor
	selected := false
	for i, matcher := range matchers {
		matched, err := matcher(descriptors...)
		if err == nil {
			desc = matched
			selected = true
			break
		}
		xlog.C(ctx).Debugf("failed to select manifest with matcher %d: %s", i, err)
	}
	if !selected {
		xlog.C(ctx).Warnf("no manifest selected with matchers, use the first as default")
		desc = descriptors[0]
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
	return func(descs ...imgspecv1.Descriptor) (imgspecv1.Descriptor, error) {
		var zero imgspecv1.Descriptor
		found, ok := lo.Find(descs, func(desc imgspecv1.Descriptor) bool {
			return desc.Digest == dgst
		})
		if ok {
			return found, nil
		}
		return zero, errdefs.Newf(errdefs.ErrNotFound, "no descriptor matched with digest %q", dgst)
	}
}

// DescriptorMatcherByPlatform returns a DescriptorMatcher that selects a descriptor by the platform applied.
func DescriptorMatcherByPlatform(target *imgspecv1.Platform) DescriptorMatcher {
	p := platforms.DefaultSpec()
	if target != nil {
		p = *target
	}
	matcher := platforms.OnlyStrict(p)
	return func(descs ...imgspecv1.Descriptor) (imgspecv1.Descriptor, error) {
		var zero imgspecv1.Descriptor
		found, ok := lo.Find(descs, func(desc imgspecv1.Descriptor) bool {
			if desc.Platform == nil {
				return false
			}
			return matcher.Match(*desc.Platform)
		})
		if ok {
			return found, nil
		}
		return zero, errdefs.Newf(errdefs.ErrNotFound, "no descriptor matched with platform %s", platforms.Format(p))
	}
}

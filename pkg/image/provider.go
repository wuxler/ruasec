package image

import (
	"context"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
)

// Provider is the minimal interface for a image readonly storage.
type Provider interface {
	// Name returns the unique identity name of the provider.
	Name() string

	// Image creates a new image specified by ref.
	//
	// NOTE: The image must be closed when processing is finished.
	Image(ctx context.Context, ref string, opts ...QueryOption) (ocispec.ImageCloser, error)
}

// MakeQueryOptions returns the options with all optional parameters applied.
func MakeQueryOptions(opts ...QueryOption) *QueryOptions {
	query := &QueryOptions{}
	for _, opt := range opts {
		opt(query)
	}
	return query
}

// QueryOptions is the structure of the optional parameters.
type QueryOptions struct {
	Platform       *imgspecv1.Platform
	InstanceDigest digest.Digest
}

// QueryOption is the optional parameter setting method.
type QueryOption func(*QueryOptions)

// WithPlatform sets the platform of the target image when the ref contains multiple
// instances.
func WithPlatform(platform *imgspecv1.Platform) QueryOption {
	return func(query *QueryOptions) {
		query.Platform = platform
	}
}

// WithImageID sets the instance digest of the target image when the ref contains multiple
// instances.
func WithInstanceDigest(dgst digest.Digest) QueryOption {
	return func(query *QueryOptions) {
		query.InstanceDigest = dgst
	}
}

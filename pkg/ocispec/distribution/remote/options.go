package remote

import (
	"strings"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
)

var (
	defaultRequestedManifestMediaTypes = []string{
		ocispec.MediaTypeDockerV2S2Manifest,
		ocispec.MediaTypeDockerV2S2ManifestList,
		ocispec.MediaTypeImageManifest,
		ocispec.MediaTypeImageIndex,
		ocispec.MediaTypeDockerV2S1Manifest,
		ocispec.MediaTypeDockerV2S1SignedManifest,
	}
)

func manifestAcceptHeader(mediaTypes ...string) string {
	if len(mediaTypes) == 0 {
		mediaTypes = defaultRequestedManifestMediaTypes
	}
	return strings.Join(mediaTypes, ", ")
}

// DefaultOptions returns the default options.
func DefaultOptions() *Options {
	return &Options{
		HTTPClient: distribution.NewClient(),
	}
}

// MakeOptions returns the options with all optional parameters applied.
func MakeOptions(opts ...Option) *Options {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	return options
}

// Option is the optional parameter setting method.
type Option func(*Options)

// Options is the structure of the optional parameters.
type Options struct {
	HTTPClient distribution.HTTPClient
}

// WithHTTPClient sets the HTTP client for the registry.
func WithHTTPClient(client distribution.HTTPClient) Option {
	return func(o *Options) {
		if client != nil {
			o.HTTPClient = client
		}
	}
}

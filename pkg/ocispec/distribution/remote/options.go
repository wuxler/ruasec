package remote

import "github.com/wuxler/ruasec/pkg/ocispec/remote"

// DefaultOptions returns the default options.
func DefaultOptions() *Options {
	return &Options{
		Client: remote.NewClient(),
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
	Client *remote.Client
}

// WithHTTPClient sets the HTTP client for the registry.
func WithHTTPClient(client *remote.Client) Option {
	return func(o *Options) {
		if client != nil {
			o.Client = client
		}
	}
}

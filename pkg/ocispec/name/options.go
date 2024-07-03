package name

func makeOptions(opts ...Option) options {
	opt := options{
		defaultRegistry: DefaultRegistry,
		defaultTag:      DefaultTag,
	}
	for _, o := range opts {
		o(&opt)
	}
	return opt
}

type options struct {
	strict          bool
	defaultRegistry string
	defaultTag      string
}

// Option is a functional option for name parsing.
type Option func(*options)

// WithStrict sets the parse mode. When set to "true", it enforces strict
// parsing rules, requiring image references to be fully specified. This
// disables default behavior and returns an error if any inconsistencies are
// found during parsing.
func WithStrict(strict bool) Option {
	return func(o *options) {
		o.strict = strict
	}
}

// WithDefaultRegistry sets the default registry that will be used if one is not
// provided. If not set, "registry-1.docker.io" will be used as default.
func WithDefaultRegistry(registry string) Option {
	return func(o *options) {
		o.defaultRegistry = registry
	}
}

// WithDefaultTag sets the default tag that will be used if one is not provided.
// If not set, "latest" will be used as default.
func WithDefaultTag(tag string) Option {
	return func(o *options) {
		o.defaultTag = tag
	}
}

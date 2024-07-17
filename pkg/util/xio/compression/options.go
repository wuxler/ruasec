package compression

// MakeOptions returns the options with all optional parameters applied.
func MakeOptions(opts ...Option) *Options {
	o := &Options{}
	for _, apply := range opts {
		apply(o)
	}
	return o
}

// UncompressOptions is used to uncompress target.
type UncompressOptions struct {
	Multithread bool
}

// CompressOptions is used to compress target.
type CompressOptions struct {
	Level       *int
	Force       bool
	Multithread bool
}

// Option is the optional parameter setting method.
type Option func(o *Options)

// Options is the composite options used to compress or uncompress.
type Options struct {
	Level       *int
	Force       bool
	Multithread bool
}

// CompressOptions returns the options used to compress.
func (o *Options) CompressOptions() *CompressOptions {
	return &CompressOptions{
		Level:       o.Level,
		Force:       o.Force,
		Multithread: o.Multithread,
	}
}

// UncompressOptions returns the options used to uncompress.
func (o *Options) UncompressOptions() *UncompressOptions {
	return &UncompressOptions{
		Multithread: o.Multithread,
	}
}

// WithLevel sets compress level.
func WithLevel(lvl int) Option {
	return func(o *Options) {
		o.Level = &lvl
	}
}

// WithMultithread sets the parallel to compress/uncompress.
func WithMultithread(multithread bool) Option {
	return func(o *Options) {
		o.Multithread = multithread
	}
}

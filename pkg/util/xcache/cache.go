package xcache

import (
	"context"

	"github.com/wuxler/ruasec/pkg/util/xgeneric"
)

type Cache[T any] interface {
	// Get returns the value of the key.
	Get(ctx context.Context, key string, options ...Option[T]) (T, bool)
	// Set saves the value of the key.
	Set(ctx context.Context, key string, value T, options ...Option[T])
	// Delete removes the value of the key.
	Delete(ctx context.Context, key string)
}

// ValueLoader is a function that loads the value of the key.
type ValueLoader[T any] func(ctx context.Context, key string) (T, bool)

// Option is a function that sets options.
type Option[T any] func(*Options[T])

// Options is the options for Get or Set.
type Options[T any] struct {
	Loader ValueLoader[T]
}

// WithLoader sets the value loader if not found.
func WithLoader[T any](loader ValueLoader[T]) Option[T] {
	return func(o *Options[T]) {
		o.Loader = loader
	}
}

// MakeOptions returns a new options.
func MakeOptions[T any](options ...Option[T]) *Options[T] {
	o := &Options[T]{}
	for _, apply := range options {
		apply(o)
	}
	if o.Loader == nil {
		o.Loader = func(_ context.Context, key string) (T, bool) {
			return xgeneric.ZeroValue[T](), false
		}
	}
	return o
}

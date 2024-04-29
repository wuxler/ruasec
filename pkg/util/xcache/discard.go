package xcache

import (
	"context"

	"github.com/wuxler/ruasec/pkg/util/xgeneric"
)

// NewDiscard returns a new cache implementation which discard all oprations.
func NewDiscard[T any]() Cache[T] {
	return discardCacheImpl[T]{}
}

type discardCacheImpl[T any] struct {
}

// Get returns the value of the target registry.
func (s discardCacheImpl[T]) Get(_ context.Context, key string, options ...Option[T]) (T, bool) {
	return xgeneric.ZeroValue[T](), false
}

// Set saves the value of the target registry.
func (s discardCacheImpl[T]) Set(_ context.Context, key string, value T, options ...Option[T]) {
}

// Delete removes the value of the target registry host.
func (s discardCacheImpl[T]) Delete(_ context.Context, key string) {
}

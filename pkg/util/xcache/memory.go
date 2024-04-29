package xcache

import (
	"context"
	"math"
	"time"

	"github.com/maypok86/otter"
	"golang.org/x/sync/singleflight"

	"github.com/wuxler/ruasec/pkg/util/xgeneric"
)

// NewMemory returns a new cache implementation based on memory.
func NewMemory[T any]() Cache[T] {
	capacity := math.MaxInt
	ttl := time.Hour

	cache, err := otter.MustBuilder[string, T](capacity).
		WithTTL(ttl).
		Build()
	if err != nil {
		panic(err)
	}
	return &memoryCacheImpl[T]{
		cache: cache,
	}
}

type memoryCacheImpl[T any] struct {
	cache     otter.Cache[string, T]
	loadGroup singleflight.Group
}

// Get returns the value of the key.
func (s *memoryCacheImpl[T]) Get(ctx context.Context, key string, options ...Option[T]) (T, bool) {
	o := MakeOptions(options...)
	v, ok := s.cache.Get(key)
	if ok {
		return v, true
	}
	loaded, err, _ := s.loadGroup.Do(key, func() (interface{}, error) {
		value, ok := o.Loader(ctx, key)
		if ok {
			s.cache.Set(key, value)
		}
		return value, nil
	})
	if err != nil {
		return xgeneric.ZeroValue[T](), false
	}
	return loaded.(T), true
}

// Put returns the value of the key.
func (s *memoryCacheImpl[T]) Set(_ context.Context, key string, value T, options ...Option[T]) {
	s.cache.Set(key, value)
}

// Delete removes the value of the key.
func (s *memoryCacheImpl[T]) Delete(_ context.Context, key string) {
	s.cache.Delete(key)
}

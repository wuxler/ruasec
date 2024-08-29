package xcontext

import (
	"context"
	"fmt"
	"strings"
)

type contextKey[T any] struct{}

// NonBlockingCheck checks context as non-blocking select and returns error if context is done.
func NonBlockingCheck(ctx context.Context, msgs ...string) error {
	select {
	case <-ctx.Done():
		if len(msgs) == 0 {
			return ctx.Err()
		}
		return fmt.Errorf("%s: %w", strings.Join(msgs, ":"), ctx.Err())
	default:
	}
	return nil
}

// WithValue returns a new Context that carries a key-value pair.
func WithValue[T any](ctx context.Context, value T) context.Context {
	key := contextKey[T]{}
	return context.WithValue(ctx, key, value)
}

// GetValue returns the value stored in the context for the given type.
func GetValue[T any](ctx context.Context) (T, bool) {
	var zero T
	if ctx == nil {
		return zero, false
	}
	key := contextKey[T]{}
	got := ctx.Value(key)
	if got == nil {
		return zero, false
	}
	value, ok := got.(T)
	return value, ok
}

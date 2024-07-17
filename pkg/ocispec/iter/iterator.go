package iter

import (
	"context"
	"errors"
)

var _ Iterator[string] = IteratorFunc[string](nil)

var (
	// ErrIteratorDone indicates the iterator is complete.
	ErrIteratorDone = errors.New("iterator done")
)

// Iterator is the interface for list operation.
type Iterator[T any] interface {
	// Next called for next page. If no more items to iterate, returns error with [ErrIteratorDone].
	Next(ctx context.Context) ([]T, error)
}

// IteratorFunc is a function that implements [Iterator].
type IteratorFunc[T any] func(context.Context) ([]T, error)

// Next called for next page.
func (fn IteratorFunc[T]) Next(ctx context.Context) ([]T, error) {
	return fn(ctx)
}

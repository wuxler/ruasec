package xlog

import (
	"context"
)

var (
	// C is a short alias of FromContext function
	C = FromContext
)

type contextKey struct{}

// FromContext get Logger from context, if not found then return global one
func FromContext(ctx context.Context) *Logger {
	if ctx == nil {
		ctx = context.Background()
	}
	logger, ok := ctx.Value(contextKey{}).(*Logger)
	if !ok {
		logger = Default()
	}
	return logger
}

// WithContext injects a Logger into context.Context and returns a new child context.Context
func WithContext(ctx context.Context, args ...any) context.Context {
	logger := FromContext(ctx)
	return context.WithValue(ctx, contextKey{}, logger.With(args...))
}

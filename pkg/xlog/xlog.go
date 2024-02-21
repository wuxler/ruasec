// Package xlog extends log/slog with some features.
package xlog

import (
	"context"
	"log/slog"
	"sync/atomic"
)

var (
	defaultLogger atomic.Value
)

func init() {
	c := NewConfig()
	defaultLogger.Store(New(c))
}

// Default returns the default Logger.
func Default() *Logger { return defaultLogger.Load().(*Logger) }

// SetDefault makes l the default Logger.
// After this call, output from the log package's default Logger
// (as with [log.Print], etc.) will be logged at LevelInfo using l's Handler.
func SetDefault(l *Logger) {
	defaultLogger.Store(l)
}

// SetLevel calls Logger.SetLevel on the default logger.
func SetLevel(lvl slog.Level) {
	Default().SetLevel(lvl)
}

// Debug calls Logger.Debug on the default logger.
func Debug(msg string, args ...any) {
	Default().AddCallerSkip(1).Debug(msg, args...)
}

// DebugContext calls Logger.DebugContext on the default logger.
func DebugContext(ctx context.Context, msg string, args ...any) {
	Default().AddCallerSkip(1).DebugContext(ctx, msg, args...)
}

// Debugf calls Logger.Debugf on the default logger.
func Debugf(format string, args ...any) {
	Default().AddCallerSkip(1).Debugf(format, args...)
}

// DebugfContext calls Logger.DebugfContext on the default logger.
func DebugfContext(ctx context.Context, format string, args ...any) {
	Default().AddCallerSkip(1).DebugfContext(ctx, format, args...)
}

// Info calls Logger.Info on the default logger.
func Info(msg string, args ...any) {
	Default().AddCallerSkip(1).Info(msg, args...)
}

// InfoContext calls Logger.InfoContext on the default logger.
func InfoContext(ctx context.Context, msg string, args ...any) {
	Default().AddCallerSkip(1).InfoContext(ctx, msg, args...)
}

// Infof calls Logger.Infof on the default logger.
func Infof(format string, args ...any) {
	Default().AddCallerSkip(1).Infof(format, args...)
}

// InfofContext calls Logger.InfofContext on the default logger.
func InfofContext(ctx context.Context, format string, args ...any) {
	Default().AddCallerSkip(1).InfofContext(ctx, format, args...)
}

// Warn calls Logger.Warn on the default logger.
func Warn(msg string, args ...any) {
	Default().AddCallerSkip(1).Warn(msg, args...)
}

// WarnContext calls Logger.WarnContext on the default logger.
func WarnContext(ctx context.Context, msg string, args ...any) {
	Default().AddCallerSkip(1).WarnContext(ctx, msg, args...)
}

// Warnf calls Logger.Warnf on the default logger.
func Warnf(format string, args ...any) {
	Default().AddCallerSkip(1).Warnf(format, args...)
}

// WarnfContext calls Logger.WarnfContext on the default logger.
func WarnfContext(ctx context.Context, format string, args ...any) {
	Default().AddCallerSkip(1).WarnfContext(ctx, format, args...)
}

// Error calls Logger.Error on the default logger.
func Error(msg string, args ...any) {
	Default().AddCallerSkip(1).Error(msg, args...)
}

// ErrorContext calls Logger.ErrorContext on the default logger.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Default().AddCallerSkip(1).ErrorContext(ctx, msg, args...)
}

// Errorf calls Logger.Errorf on the default logger.
func Errorf(format string, args ...any) {
	Default().AddCallerSkip(1).Errorf(format, args...)
}

// ErrorfContext calls Logger.ErrorfContext on the default logger.
func ErrorfContext(ctx context.Context, format string, args ...any) {
	Default().AddCallerSkip(1).ErrorfContext(ctx, format, args...)
}

// Log calls Logger.Log on the default logger.
func Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	Default().AddCallerSkip(1).Log(ctx, level, msg, args...)
}

// LogAttrs calls Logger.LogAttrs on the default logger.
func LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	Default().AddCallerSkip(1).LogAttrs(ctx, level, msg, attrs...)
}

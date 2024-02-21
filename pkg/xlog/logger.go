package xlog

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"
)

const (
	// skip [runtime.Callers, this function, this function's caller]
	defaultCallerSkip = 3
)

// New creates a new Logger with the given non-nil Handler.
func New(c Config) *Logger {
	h := c.BuildHandler()
	if h == nil {
		panic("nil Handler")
	}
	return &Logger{handler: h, callerSkip: defaultCallerSkip}
}

// Logger extends slog.Logger with additional features.
type Logger struct {
	handler    slog.Handler
	callerSkip int
}

func (l *Logger) clone() *Logger {
	c := *l
	return &c
}

// SetLevel supports to change level dynamicly.
func (l *Logger) SetLevel(lvl slog.Level) {
	SetHandlerLevel(l.Handler(), lvl)
}

// AddCallerSkip increases the number of callers skipped by caller annotation.
func (l *Logger) AddCallerSkip(skip int) *Logger {
	c := l.clone()
	c.callerSkip += skip
	return c
}

// Handler returns l's Handler.
func (l *Logger) Handler() slog.Handler { return l.handler }

// With returns a Logger that includes the given attributes
// in each output operation. Arguments are converted to
// attributes as if by [Logger.Log].
func (l *Logger) With(args ...any) *Logger {
	if len(args) == 0 {
		return l
	}
	c := l.clone()
	c.handler = l.handler.WithAttrs(argsToAttrSlice(args))
	return c
}

// WithGroup returns a Logger that starts a group, if name is non-empty.
// The keys of all attributes added to the Logger will be qualified by the given
// name. (How that qualification happens depends on the [Handler.WithGroup]
// method of the Logger's Handler.)
//
// If name is empty, WithGroup returns the receiver.
func (l *Logger) WithGroup(name string) *Logger {
	if name == "" {
		return l
	}
	c := l.clone()
	c.handler = l.handler.WithGroup(name)
	return c
}

// EnabledContext reports whether l emits log records at the given context and level.
func (l *Logger) EnabledContext(ctx context.Context, level slog.Level) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	return l.Handler().Enabled(ctx, level)
}

// Enabled reports whether l emits log records at the given context and level.
func (l *Logger) Enabled(level slog.Level) bool {
	return l.Handler().Enabled(context.Background(), level)
}

// Log emits a log record with the current time and the given level and message.
// The Record's Attrs consist of the Logger's attributes followed by
// the Attrs specified by args.
//
// The attribute arguments are processed as follows:
//   - If an argument is an Attr, it is used as is.
//   - If an argument is a string and this is not the last argument,
//     the following argument is treated as the value and the two are combined
//     into an Attr.
//   - Otherwise, the argument is treated as a value with key "!BADKEY".
func (l *Logger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	l.log(ctx, level, msg, args...)
}

// Logf is a helper method to format message with args instead of Attrs.
func (l *Logger) Logf(ctx context.Context, level slog.Level, format string, args ...any) {
	l.log(ctx, level, fmt.Sprintf(format, args...))
}

// LogAttrs is a more efficient version of [Logger.Log] that accepts only Attrs.
func (l *Logger) LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	l.logAttrs(ctx, level, msg, attrs...)
}

// Debug logs at LevelDebug.
func (l *Logger) Debug(msg string, args ...any) {
	l.log(context.Background(), slog.LevelDebug, msg, args...)
}

// DebugContext logs at LevelDebug with the given context.
func (l *Logger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelDebug, msg, args...)
}

// Debugf logs at LevelDebug with the given format.
func (l *Logger) Debugf(format string, args ...any) {
	l.log(context.Background(), slog.LevelDebug, fmt.Sprintf(format, args...))
}

// DebugfContext logs at LevelDebug with the given format and context.
func (l *Logger) DebugfContext(ctx context.Context, format string, args ...any) {
	l.log(ctx, slog.LevelDebug, fmt.Sprintf(format, args...))
}

// Info logs at LevelInfo.
func (l *Logger) Info(msg string, args ...any) {
	l.log(context.Background(), slog.LevelInfo, msg, args...)
}

// InfoContext logs at LevelInfo with the given context.
func (l *Logger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelInfo, msg, args...)
}

// Infof logs at LevelInfo with the given format.
func (l *Logger) Infof(format string, args ...any) {
	l.log(context.Background(), slog.LevelInfo, fmt.Sprintf(format, args...))
}

// InfofContext logs at LevelInfo with the given format and context.
func (l *Logger) InfofContext(ctx context.Context, format string, args ...any) {
	l.log(ctx, slog.LevelInfo, fmt.Sprintf(format, args...))
}

// Warn logs at LevelWarn.
func (l *Logger) Warn(msg string, args ...any) {
	l.log(context.Background(), slog.LevelWarn, msg, args...)
}

// WarnContext logs at LevelWarn with the given context.
func (l *Logger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelWarn, msg, args...)
}

// Warnf logs at LevelWarn with the given format.
func (l *Logger) Warnf(format string, args ...any) {
	l.log(context.Background(), slog.LevelWarn, fmt.Sprintf(format, args...))
}

// WarnfContext logs at LevelWarn with the given format and context.
func (l *Logger) WarnfContext(ctx context.Context, format string, args ...any) {
	l.log(ctx, slog.LevelWarn, fmt.Sprintf(format, args...))
}

// Error logs at LevelError.
func (l *Logger) Error(msg string, args ...any) {
	l.log(context.Background(), slog.LevelError, msg, args...)
}

// ErrorContext logs at LevelError with the given context.
func (l *Logger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelError, msg, args...)
}

// Errorf logs at LevelError with the given format.
func (l *Logger) Errorf(format string, args ...any) {
	l.log(context.Background(), slog.LevelError, fmt.Sprintf(format, args...))
}

// ErrorfContext logs at LevelError with the given format and context.
func (l *Logger) ErrorfContext(ctx context.Context, format string, args ...any) {
	l.log(ctx, slog.LevelError, fmt.Sprintf(format, args...))
}

// log is the low-level logging method for methods that take ...any.
// It must always be called directly by an exported logging method
// or function, because it uses a fixed call depth to obtain the pc.
func (l *Logger) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if !l.EnabledContext(ctx, level) {
		return
	}
	var pc uintptr
	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(l.callerSkip, pcs[:])
	pc = pcs[0]
	r := slog.NewRecord(time.Now(), level, msg, pc)
	r.Add(args...)
	if ctx == nil {
		ctx = context.Background()
	}
	_ = l.Handler().Handle(ctx, r) //nolint:errcheck
}

// logAttrs is like [Logger.log], but for methods that take ...Attr.
func (l *Logger) logAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	if !l.EnabledContext(ctx, level) {
		return
	}
	var pc uintptr
	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(l.callerSkip, pcs[:])
	pc = pcs[0]
	r := slog.NewRecord(time.Now(), level, msg, pc)
	r.AddAttrs(attrs...)
	if ctx == nil {
		ctx = context.Background()
	}
	_ = l.Handler().Handle(ctx, r) //nolint:errcheck
}

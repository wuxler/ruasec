package xlog

import (
	"fmt"
	"log/slog"
)

// alias
const (
	badKey = "!BADKEY"

	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type (
	// Handler alias slog.Handler
	Handler = slog.Handler
	// Level alias slog.Level
	Level = slog.Level
	// Attr alias slog.Attr
	Attr = slog.Attr
)

// NewLevelVar returns a *slog.LevelVar with input level.
func NewLevelVar(lvl slog.Level) *slog.LevelVar {
	v := &slog.LevelVar{}
	v.Set(lvl)
	return v
}

// argsToAttr turns a prefix of the nonempty args slice into an Attr
// and returns the unconsumed portion of the slice.
// If args[0] is an Attr, it returns it.
// If args[0] is a string, it treats the first two elements as
// a key-value pair.
// Otherwise, it treats args[0] as a value with a missing key.
func argsToAttr(args []any) (slog.Attr, []any) {
	switch x := args[0].(type) {
	case string:
		if len(args) == 1 {
			return slog.String(badKey, x), nil
		}
		return slog.Any(x, args[1]), args[2:]

	case slog.Attr:
		return x, args[1:]

	default:
		return slog.Any(badKey, x), args[1:]
	}
}

func argsToAttrSlice(args []any) []slog.Attr {
	var (
		attr  slog.Attr
		attrs []slog.Attr
	)
	for len(args) > 0 {
		attr, args = argsToAttr(args)
		attrs = append(attrs, attr)
	}
	return attrs
}

func try(callback func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("unexpected error: %+v", r)
			}
		}
	}()

	err = callback()

	return
}

package xlog

import (
	"context"
	"io"
	"log/slog"

	"github.com/samber/lo"
)

// HandlerCreator is a function type to create slog.Handler.
type HandlerCreator func(w io.Writer, opts *slog.HandlerOptions) slog.Handler

var (
	// JSONHandlerCreator wraps slog.NewJSONHandler as HandlerCreator
	JSONHandlerCreator HandlerCreator = func(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
		return slog.NewJSONHandler(w, opts)
	}
	// TextHandlerCreator wraps slog.NewTextHandler as HandlerCreator
	TextHandlerCreator HandlerCreator = func(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
		return slog.NewTextHandler(w, opts)
	}
)

// LeveledHandler wraps slog.Handler with SetLevel() method.
type LeveledHandler interface {
	slog.Handler
	// SetLevel changes level dynamicly.
	SetLevel(lvl slog.Level)
}

// SetHandlerLevel asserts input slog.Handler as LeveledHandler and call SetLevel() method.
func SetHandlerLevel(h slog.Handler, lvl slog.Level) {
	if leveled, ok := h.(LeveledHandler); ok {
		leveled.SetLevel(lvl)
	}
}

// NewLeveledHandlerCreator wraps a HandlerCreator to create a LeveledHandler.
func NewLeveledHandlerCreator(create HandlerCreator) HandlerCreator {
	return func(w io.Writer, o *slog.HandlerOptions) slog.Handler {
		opts := slog.HandlerOptions{}
		if o != nil {
			opts = *o
		}
		lvl := slog.LevelInfo
		if opts.Level != nil {
			lvl = opts.Level.Level()
		}
		lvlVar := NewLevelVar(lvl)
		opts.Level = lvlVar

		handler := create(w, &opts)
		return &leveledHandler{handler: handler, level: lvlVar}
	}
}

type leveledHandler struct {
	handler slog.Handler
	level   *slog.LevelVar
}

// Enabled reports whether the handler handles records at the given level.
func (h *leveledHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.handler.Enabled(ctx, lvl)
}

// Handle handles the Record.
func (h *leveledHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h.handler.WithAttrs(attrs)
}

// WithGroup returns a new Handler with the given group appended to
// the receiver's existing groups.
func (h *leveledHandler) WithGroup(name string) slog.Handler {
	return h.handler.WithGroup(name)
}

// Handle handles the Record.
func (h *leveledHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.handler.Handle(ctx, r)
}

// SetLevel changes level dynamicly.
func (h *leveledHandler) SetLevel(lvl slog.Level) {
	h.level.Set(lvl)
}

// MultiHandler distributes records to multiple slog.Handler.
func MultiHandler(handlers ...slog.Handler) slog.Handler {
	return &multiHandler{handlers: handlers}
}

type multiHandler struct {
	handlers []slog.Handler
}

// Enabled implements slog.Handler
func (h *multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for i := range h.handlers {
		if h.handlers[i].Enabled(ctx, l) {
			return true
		}
	}

	return false
}

// Handle implements slog.Handler
//
// FIXME(wuxler): should we return multiple errors?
func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for i := range h.handlers {
		if h.handlers[i].Enabled(ctx, r.Level) {
			err := try(func() error {
				return h.handlers[i].Handle(ctx, r.Clone())
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// WithAttrs implements slog.Handler
func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handers := lo.Map(h.handlers, func(h slog.Handler, _ int) slog.Handler {
		return h.WithAttrs(attrs)
	})
	return MultiHandler(handers...)
}

// WithGroup implements slog.Handler
func (h *multiHandler) WithGroup(name string) slog.Handler {
	handers := lo.Map(h.handlers, func(h slog.Handler, _ int) slog.Handler {
		return h.WithGroup(name)
	})
	return MultiHandler(handers...)
}

// SetLevel implements LeveledHandler
func (h *multiHandler) SetLevel(lvl slog.Level) {
	lo.ForEach(h.handlers, func(item slog.Handler, _ int) {
		SetHandlerLevel(item, lvl)
	})
}

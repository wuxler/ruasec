package xlog

import (
	"log/slog"
	"path/filepath"
)

// AttrReplacer is called to rewrite each non-group attribute before it is logged.
type AttrReplacer func(groups []string, attr slog.Attr) Attr

// ChainReplacer calls replacers in order.
func ChainReplacer(replacers ...AttrReplacer) AttrReplacer {
	return func(groups []string, attr slog.Attr) Attr {
		rewrite := attr
		for _, repl := range replacers {
			rewrite = repl(groups, rewrite)
		}
		return rewrite
	}
}

// NormalizeSourceAttrReplacer replaces source file path as basename.
func NormalizeSourceAttrReplacer() AttrReplacer {
	return func(groups []string, attr slog.Attr) Attr {
		// Remove the directory from the source's filename.
		if attr.Key == slog.SourceKey {
			if source, ok := attr.Value.Any().(*slog.Source); ok {
				source.File = filepath.Base(source.File)
			}
		}
		return attr
	}
}

// SuppressTimeAttrReplacer removes the top-level time attribute.
// It is intended to be used as a ReplaceAttr function,
// to make example output deterministic.
func SuppressTimeAttrReplacer() AttrReplacer {
	return func(groups []string, attr slog.Attr) Attr {
		if attr.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Attr{}
		}
		return attr
	}
}

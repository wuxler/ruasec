package xfs

import (
	"context"
	"io/fs"
)

// Getter can return a filesystem.
type Getter interface {
	// GetFS returns a filesystem.
	GetFS(ctx context.Context) (fs.FS, error)
}

// GetterFunc is a function that implements FSGetter.
type GetterFunc func(ctx context.Context) (fs.FS, error)

// GetFS implements FSGetter.
func (fn GetterFunc) GetFS(ctx context.Context) (fs.FS, error) {
	return fn(ctx)
}

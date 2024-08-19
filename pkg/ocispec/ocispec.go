package ocispec

import (
	"context"
	"io"
	"io/fs"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Describable defines a resource that can be described.
type Describable interface {
	// Descriptor returns the descriptor for the resource.
	Descriptor() imgspecv1.Descriptor
}

// Compressor can compress data.
type Compressor interface {
	// Compressed returns a reader that compressed what is read.
	// The reader must be closed when reading is finished.
	Compressed(ctx context.Context) (io.ReadCloser, error)
}

// Uncompressor can uncompress data.
type Uncompressor interface {
	// Uncompressed returns a reader that uncompresses what is read.
	// The reader must be closed when reading is finished.
	Uncompressed(ctx context.Context) (io.ReadCloser, error)
}

// FSGetter can return a filesystem.
type FSGetter interface {
	// GetFS returns a filesystem.
	GetFS(ctx context.Context) (fs.FS, error)
}

// FSGetterFunc is a function that implements FSGetter.
type FSGetterFunc func(ctx context.Context) (fs.FS, error)

// GetFS implements FSGetter.
func (fn FSGetterFunc) GetFS(ctx context.Context) (fs.FS, error) {
	return fn(ctx)
}

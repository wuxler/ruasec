package ocispec

import (
	"context"
	"io"

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

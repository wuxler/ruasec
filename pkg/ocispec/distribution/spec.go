package distribution

import (
	"context"
	"io"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/iter"
)

const (
	// DefaultChunkSize is used when chunk size is not set and minimum chunk size from
	// server is not found in response.
	DefaultChunkSize = 64 * 1024 // 64 KiB
)

// Spec defines a generic interface to a single OCI registry.
// It does not support cross-registry operations: all methods are
// directed to the receiver only.
type Spec interface {
	// GetVersion checks the registry accessible and returns the properties of the registry.
	GetVersion(ctx context.Context) (string, error)
	// StatManifest returns the descriptor of the manifest with the given reference.
	StatManifest(ctx context.Context, repo string, reference string) (imgspecv1.Descriptor, error)
	// GetManifest returns the content of the manifest with the given reference.
	GetManifest(ctx context.Context, repo string, reference string) (cas.ReadCloser, error)
	// StatBlob returns the descriptor of the blob with the given digest.
	StatBlob(ctx context.Context, repo string, dgst digest.Digest) (imgspecv1.Descriptor, error)
	// GetBlob returns the content of the blob with the given digest.
	GetBlob(ctx context.Context, repo string, dgst digest.Digest) (cas.ReadCloser, error)

	// PushManifest pushes a manifest with the given descriptor and tags.
	PushManifest(ctx context.Context, repo string, r cas.Reader, tags ...string) error
	// PushBlob pushes a blob monolithically to the given repository, reading the descriptor
	// and content from "getter".
	//
	// Push is done by conventional 2-step monolithic upload instead of a single
	// `POST` request for better overall performance. It also allows early fail on
	// authentication errors.
	PushBlob(ctx context.Context, repo string, getter cas.ReadCloserGetter) error
	// PushBlobChunked starts to push a blob to the given repository.
	// The returned [BlobWriteCloser] can be used to stream the upload and resume on
	// temporary errors.
	//
	// The chunkSize parameter provides a hint for the chunk size to use when writing
	// to the registry. If it's zero, a suitable default will be chosen. It might be
	// larger if the underlying registry requires that.
	//
	// The context remains active as long as the BlobWriteCloser is around: if it's
	// canceled, it should cause any blocked BlobWriteCloser operations to terminate.
	PushBlobChunked(ctx context.Context, repo string, chunkSize int64) (BlobWriteCloser, error)
	// PushBlobChunkedResume resumes a previous push of a blob started with PushBlobChunked.
	// The id should be the value returned from [BlobWriteCloser.ID] from the previous push.
	// and the offset should be the value returned from [BlobWriteCloser.Size].
	//
	// The offset and chunkSize should similarly be obtained from the previous [BlobWriterCloser]
	// via the [BlobWriteCloser.Size] and [BlobWriteCloser.ChunkSize] methods.
	// Alternatively, set offset to -1 to continue where the last write left off,
	// and to only use chunkSize as a hint like in PushBlobChunked.
	//
	// The context remains active as long as the BlobWriteCloser is around: if it's
	// canceled, it should cause any blocked BlobWriteCloser operations to terminate.
	PushBlobChunkedResume(ctx context.Context, repo string, chunkSize int64, id string, offset int64) (BlobWriteCloser, error)
	// MountBlob makes a blob with the given digest that's in "from" repository available
	// in "repo" repository and returns mounted successfully or not.
	//
	// As [distribution-spec] specified:
	//
	// "Alternatively, if a registry does not support cross-repository mounting or is unable
	// to mount the requested blob, it SHOULD return a 202. This indicates that the upload
	// session has begun and that the client MAY proceed with the upload."
	//
	// So the returns composites as follow:
	//   - "true, nil" means mount succeed.
	//   - "false, nil" means mount is unsupported.
	//   - "false, err" means mount failed with unexpected error.
	//
	// [distribution-spec]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#mounting-a-blob-from-another-repository
	MountBlob(ctx context.Context, repo string, from string, dgst digest.Digest) (bool, error)

	// DeleteManifest deletes the manifest with the given digest in the given repository.
	DeleteManifest(ctx context.Context, repo string, reference string) error
	// DeleteBlob deletes the blob with the given digest in the given repository.
	DeleteBlob(ctx context.Context, repo string, dgst digest.Digest) error

	// ListRepositories returns an iterator that can be used to iterate
	// over all the repositories in the registry in order.
	ListRepositories(opts ...ListOption) iter.Iterator[string]
	// ListTags returns an iterator that can be used to iterate over all
	// the tags in the given repository in order.
	ListTags(repo string, opts ...ListOption) iter.Iterator[string]
	// Referrers returns an iterator that can be used to iterate over all
	// the manifests that have the given digest as their Subject.
	//
	// If "artifactType" is specified, the results will be restricted to
	// only manifests with that type.
	ListReferrers(ctx context.Context, repo string, dgst digest.Digest, artifactType string) ([]imgspecv1.Descriptor, error)
}

// BlobWriter provides a handle for uploading a blob to a registry.
type BlobWriteCloser interface {
	// Writer writes more data to the blob. When resuming, the caller must start
	// writing data from Size bytes into the content.
	io.Writer

	// Closer closes the writer but does not abort. The blob write can later be
	// resumed.
	io.Closer

	// Size returns the number of bytes written to this blob.
	Size() int64

	// ChunkSize returns the maximum number of bytes to upload at a single time.
	// This number must meet the minimum given by the registry and should otherwise
	// follow the hint given by the user.
	ChunkSize() int64

	// ID returns the opaque identifier for this writer. The returned value
	// can be passed to PushBlobChunkedResume to resume the write.
	// It is only valid before Write has been called or after Close has
	// been called.
	ID() string

	// Commit completes the blob writer process. The content is verified against
	// the provided digest, and a canonical descriptor for it is returned.
	Commit(dgst digest.Digest) (imgspecv1.Descriptor, error)

	// Cancel ends the blob write without storing any data and frees any
	// associated resources. Any data written thus far will be lost.
	// Cancel implementations should allow multiple calls even after a commit
	// that result in a no-op. This allows use of Cancel in a defer statement,
	// increasing the assurance that it is correctly called.
	// If this is not called, the unfinished uploads will eventually timeout.
	Cancel() error
}

// ListOption used as optional parameters in list function.
type ListOption func(*ListOptions)

// ListOptions is the options of the list operations.
type ListOptions struct {
	// PageSize represents each iterate page size.
	PageSize int
	// Offset represents where the list iterator should start at.
	Offset string
}

// WithPageSize sets the page size option.
func WithPageSize(size int) ListOption {
	return func(o *ListOptions) {
		o.PageSize = size
	}
}

// WithOffset sets the offset option.
func WithOffset(offset string) ListOption {
	return func(o *ListOptions) {
		o.Offset = offset
	}
}

// MakeListOptions returns the list options with all optional parameters applied.
func MakeListOptions(opts ...ListOption) *ListOptions {
	var options ListOptions
	for _, opt := range opts {
		opt(&options)
	}
	return &options
}

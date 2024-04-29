// Copyright 2023 CUE Labs AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Modifications copyright (C) 2024 RuaSec Authors
//
// The file are copied from oci[github.com/cue-labs/oci], and we keep the original copyright
// and license above.
//
// We directly considered copying the code and made modifications to the code as needed because
// we didn't want to introduce additional dependencies.
// Thanks to the original author of the code!

package distribution

import (
	"context"
	"io"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/util/xgeneric/iter"
)

// Pinger defines registry ping actions.
type Pinger interface {
	// Ping checks if the storage is reachable.
	Ping(ctx context.Context) error
}

// Reader defines registry read actions for blobs, manifests, and other resources.
type Reader interface {
	// GetManifest returns the contents of the manifest with the given digest.
	// The context also controls the lifetime of the returned ContentReadCloser.
	//
	// Errors:
	// 	- ErrNameUnknown when the repository is not present.
	// 	- ErrManifestUnknown when the blob is not present in the repository.
	GetManifest(ctx context.Context, repo string, dgst digest.Digest) (DescribableReadCloser, error)

	// GetTag returns the contents of the manifest with the given tag.
	// The context also controls the lifetime of the returned ContentReadCloser.
	//
	// Errors:
	// 	- ErrNameUnknown when the repository is not present.
	// 	- ErrManifestUnknown when the tag is not present in the repository.
	GetTag(ctx context.Context, repo string, tag string) (DescribableReadCloser, error)

	// StatManifest returns the descriptor for a given maniifest.
	// Only the MediaType, dgst and Size fields will be filled out.
	//
	// Errors:
	// 	- ErrNameUnknown when the repository is not present.
	// 	- ErrManifestUnknown when the blob is not present in the repository.
	StatManifest(ctx context.Context, repo string, dgst digest.Digest) (v1.Descriptor, error)

	// StatTag returns the descriptor for a given tag.
	// Only the MediaType, dgst and Size fields will be filled out.
	//
	// Errors:
	// 	- ErrNameUnknown when the repository is not present.
	// 	- ErrManifestUnknown when the blob is not present in the repository.
	StatTag(ctx context.Context, repo string, tag string) (v1.Descriptor, error)

	// StatBlob returns the descriptor for a given blob digest.
	// Only the MediaType, dgst and Size fields will be filled out.
	//
	// Errors:
	// 	- ErrNameUnknown when the repository is not present.
	// 	- ErrBlobUnknown when the blob is not present in the repository.
	StatBlob(ctx context.Context, repo string, dgst digest.Digest) (v1.Descriptor, error)

	// GetBlob returns the content of the blob with the given digest.
	// The context also controls the lifetime of the returned ContentReadCloser.
	//
	// Errors:
	// 	- ErrNameUnknown when the repository is not present.
	// 	- ErrBlobUnknown when the blob is not present in the repository.
	GetBlob(ctx context.Context, repo string, dgst digest.Digest) (DescribableReadCloser, error)

	// GetBlobRange is like GetBlob but asks to get only the given range of bytes from the blob,
	// starting at "start" offset, up to but not including "end" offset.
	// If "end" offset is negative or exceeds the actual size of the blob, GetBlobRange will
	// return all the data starting from "start" offset.
	// The context also controls the lifetime of the returned ContentReadCloser.
	GetBlobRange(ctx context.Context, repo string, dgst digest.Digest, start, end int64) (DescribableReadCloser, error)
}

// Writer defines registry write actions for blobs, manifests, and other resources.
type Writer interface {
	// PushBlob pushes a blob described by desc to the given repository, reading content from r.
	// Only the desc.Digest and desc.Size fields are used.
	// It returns desc with Digest set to the canonical digest for the blob.
	//
	// Errors:
	// 	- ErrNameUnknown when the repository is not present.
	// 	- ErrNameInvalid when the repository name is not valid.
	// 	- ErrDigestInvalid when desc.Digest does not match the content.
	// 	- ErrSizeInvalid when desc.Size does not match the content length.
	PushBlob(ctx context.Context, repo string, desc v1.Descriptor, r io.Reader) (v1.Descriptor, error)

	// PushBlobChunked starts to push a blob to the given repository.
	// The returned [WriteCloser] can be used to stream the upload and resume on temporary errors.
	//
	// The chunkSize parameter provides a hint for the chunk size to use
	// when writing to the registry. If it's zero, a suitable default will be chosen.
	// It might be larger if the underlying registry requires that.
	//
	// The context remains active as long as the WriteCloser is around: if it's
	// canceled, it should cause any blocked WriteCloser operations to terminate.
	PushBlobChunked(ctx context.Context, repo string, chunkSize int) (BlobWriteCloser, error)

	// PushBlobChunkedResume resumes a previous push of a blob started with PushBlobChunked.
	// The id should be the value returned from [WriteCloser.ID] from the previous push.
	// and the offset should be the value returned from [WriteCloser.Size].
	//
	// The offset and chunkSize should similarly be obtained from the previous [WriteCloser]
	// via the [WriteCloser.Size] and [WriteCloser.ChunkSize] methods.
	// Alternatively, set offset to -1 to continue where the last write left off,
	// and to only use chunkSize as a hint like in PushBlobChunked.
	//
	// The context remains active as long as the WriteCloser is around: if it's
	// canceled, it should cause any blocked WriteCloser operations to terminate.
	PushBlobChunkedResume(ctx context.Context, repo, id string, offset int64, chunkSize int) (BlobWriteCloser, error)

	// MountBlob makes a blob with the given digest that's in fromRepo available
	// in toRepo and returns its canonical descriptor.
	//
	// This avoids the need to pull content down from fromRepo only to push it to r.
	//
	// Errors:
	// 	- ErrUnsupported (when the repository does not support mounts).
	//
	// TODO(wuxler): the mount endpoint doesn't return the size of the content,
	// so to return a correctly populated descriptor, a client will need to make
	// an extra HTTP call to find that out. For now, we'll just say that
	// the descriptor returned from MountBlob might have a zero Size.
	MountBlob(ctx context.Context, fromRepo, toRepo string, dgst digest.Digest) (v1.Descriptor, error)

	// PushManifest pushes a manifest with the given media type and contents.
	// If tag is non-empty, the tag with that name will be pointed at the manifest.
	//
	// It returns a descriptor suitable for accessing the manifest.
	PushManifest(ctx context.Context, repo string, tag string, contents []byte, mediaType string) (v1.Descriptor, error)
}

// Deleter defines registry delete actions that for blobs, manifests and other resources.
type Deleter interface {
	// DeleteBlob deletes the blob with the given digest in the given repository.
	DeleteBlob(ctx context.Context, repo string, dgst digest.Digest) error

	// DeleteManifest deletes the manifest with the given digest in the given repository.
	DeleteManifest(ctx context.Context, repo string, dgst digest.Digest) error

	// DeleteTag deletes the manifest with the given tag in the given repository.
	//
	// FIXME(wuxler): does this delete the tag only, or the manifest too?
	DeleteTag(ctx context.Context, repo string, tag string) error
}

// Lister defines registry operations that enumerate objects within the registry.
// TODO(wuxler): support resumption from a given point.
type Lister interface {
	// Repositories returns an iterator that can be used to iterate
	// over all the repositories in the registry in lexical order.
	// If startAfter is non-empty, the iteration starts lexically
	// after, but not including, that repository.
	Repositories(ctx context.Context, startAfter string) iter.Seq[string]

	// Tags returns an iterator that can be used to iterate over all
	// the tags in the given repository in lexical order. If
	// startAfter is non-empty, the tags start lexically after, but
	// not including that tag.
	Tags(ctx context.Context, repo string, startAfter string) iter.Seq[string]

	// Referrers returns an iterator that can be used to iterate over all
	// the manifests that have the given digest as their Subject.
	// If artifactType is non-zero, the results will be restricted to
	// only manifests with that type.
	//
	// FIXME(wuxler): is it possible to ask for multiple artifact types?
	Referrers(ctx context.Context, repo string, dgst digest.Digest, artifactType string) iter.Seq[v1.Descriptor]
}

// BlobWriteCloser provides a handle for uploading a blob to a registry.
type BlobWriteCloser interface {
	// Write writes more data to the blob. When resuming, the
	// caller must start writing data from Size bytes into the content.
	io.Writer

	// Closer closes the writer but does not abort. The blob write
	// can later be resumed.
	io.Closer

	// Size returns the number of bytes written to this blob.
	Size() int64

	// ChunkSize returns the maximum number of bytes to upload at a single time.
	// This number must meet the minimum given by the registry
	// and should otherwise follow the hint given by the user.
	ChunkSize() int

	// ID returns the opaque identifier for this writer. The returned value
	// can be passed to PushBlobChunked to resume the write.
	// It is only valid before Write has been called or after Close has
	// been called.
	ID() string

	// Commit completes the blob writer process. The content is verified
	// against the provided digest, and a canonical descriptor for it is returned.
	Commit(digest digest.Digest) (v1.Descriptor, error)

	// Cancel ends the blob write without storing any data and frees any
	// associated resources. Any data written thus far will be lost. Cancel
	// implementations should allow multiple calls even after a commit that
	// result in a no-op. This allows use of Cancel in a defer statement,
	// increasing the assurance that it is correctly called.
	Cancel() error
}

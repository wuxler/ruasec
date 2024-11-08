package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	stdurl "net/url"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cast"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	"github.com/wuxler/ruasec/pkg/util/xhttp"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/xlog"
)

var (
	_ distribution.BlobWriteCloser = (*blobWriter)(nil)
)

type blobWriter struct {
	ctx       context.Context
	spec      *Registry
	chunkSize int64
	location  *stdurl.URL

	// mu guards the fields below it.
	mu       sync.Mutex
	closed   bool
	chunk    []byte
	closeErr error

	// size holds the size of the entire upload as seen from the
	// client perspective. Each call to Write increases this immediately.
	size int64

	// flushed holds the size of the upload as flushed to the server.
	// Each successfully flushed chunk increases this.
	flushed int64
}

func (w *blobWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// We use > rather than >= here so that using a chunk size of 100
	// and writing 100 bytes does not actually flush, which would result in a PATCH
	// then followed by an empty-bodied PUT with the call to Commit.
	// Instead, we want the writes to not flush at all, and Commit to PUT the entire chunk.
	if int64(len(w.chunk)+len(p)) > w.chunkSize {
		if err := w.flush(p, ""); err != nil {
			return 0, err
		}
	} else {
		if w.chunk == nil {
			w.chunk = make([]byte, 0, w.chunkSize)
		}
		w.chunk = append(w.chunk, p...)
	}
	w.size += int64(len(p))
	return len(p), nil
}

func (w *blobWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	err := w.flush(nil, "")
	w.closed = true
	w.closeErr = err
	return err
}

// Size returns the number of bytes written to this blob.
func (w *blobWriter) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

// ChunkSize returns the maximum number of bytes to upload at a single time.
// This number must meet the minimum given by the registry and should otherwise
// follow the hint given by the user.
func (w *blobWriter) ChunkSize() int64 {
	return w.chunkSize
}

// ID returns the opaque identifier for this writer. The returned value
// can be passed to PushBlobChunkedResume to resume the write.
// It is only valid before Write has been called or after Close has
// been called.
func (w *blobWriter) ID() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := strings.LastIndex(w.location.Path, "/")
	if idx == -1 {
		panic("invalid location: no path separator found")
	}
	return w.location.Path[idx+1:]
}

// Commit completes the blob writer process. The content is verified against
// the provided digest, and a canonical descriptor for it is returned.
func (w *blobWriter) Commit(dgst digest.Digest) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	if dgst == "" {
		return zero, errors.New("cannot commit with an empty digest")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.flush(nil, dgst); err != nil {
		return zero, fmt.Errorf("cannot flush data before commit: %w", err)
	}
	return imgspecv1.Descriptor{
		MediaType: ocispec.DefaultMediaType,
		Digest:    dgst,
		Size:      w.size,
	}, nil
}

// Cancel ends the blob write without storing any data and frees any
// associated resources. Any data written thus far will be lost.
// Cancel implementations should allow multiple calls even after a commit
// that result in a no-op. This allows use of Cancel in a defer statement,
// increasing the assurance that it is correctly called.
// If this is not called, the unfinished uploads will eventually timeout.
func (w *blobWriter) Cancel() error {
	// try to delete the upload session
	if err := w.delete(); err != nil {
		xlog.C(w.ctx).Debugf("skip, unable to invoke DELETE request to cancel: %s", err)
	}
	return nil
}

func (w *blobWriter) delete() error {
	ctx := authn.AppendScopes(w.ctx, authn.ActionDelete)
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, w.location.String(), http.NoBody)
	if err != nil {
		return err
	}
	resp, err := w.spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	return xhttp.Success(resp, http.StatusAccepted)
}

func (w *blobWriter) flush(buf []byte, commitDigest digest.Digest) error {
	if commitDigest == "" && len(buf)+len(w.chunk) == 0 {
		return nil
	}
	// start a new PATCH request to send the currently outstanding data.
	method := http.MethodPatch
	expectCode := http.StatusAccepted
	url := w.location
	if commitDigest != "" {
		// This is the final piece of data, so send it as the final PUT request
		// (committing the whole blob) which avoids an extra round trip.
		method = http.MethodPut
		expectCode = http.StatusCreated
		query := url.Query()
		query.Set("digest", commitDigest.String())
		url.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(w.ctx, method, url.String(), concatBody(w.chunk, buf))
	if err != nil {
		return err
	}
	request.ContentLength = int64(len(w.chunk) + len(buf))
	request.Header.Set("Content-Range", xhttp.RangeString(w.flushed, w.flushed+request.ContentLength))
	request.Header.Set("Content-Type", ocispec.DefaultMediaType)

	resp, err := w.spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp, expectCode); err != nil {
		return err
	}

	location, err := resp.Location()
	if err != nil {
		return xhttp.MakeResponseError(resp, fmt.Errorf("bad Location in response header: %w", err))
	}
	w.location = location
	w.flushed += request.ContentLength
	w.chunk = w.chunk[:0]
	return nil
}

// chunkSizeFromResponse returns the chunk size between server-side defined
// and default value.
//
// See https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-a-blob-in-chunks
func chunkSizeFromResponse(resp *http.Response, chunkSize int64) int64 {
	minChunkSize, err := cast.ToInt64E(resp.Header.Get("OCI-Chunk-Min-Length"))
	if err == nil && minChunkSize > chunkSize {
		return minChunkSize
	}
	return chunkSize
}

func concatBody(b1, b2 []byte) io.Reader {
	if len(b1)+len(b2) == 0 {
		return nil
	}
	if len(b1) == 0 {
		return bytes.NewReader(b2)
	}
	if len(b2) == 0 {
		return bytes.NewReader(b1)
	}
	return io.MultiReader(
		bytes.NewReader(b1),
		bytes.NewReader(b2),
	)
}

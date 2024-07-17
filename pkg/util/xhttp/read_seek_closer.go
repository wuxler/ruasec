package xhttp

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/wuxler/ruasec/pkg/util/xio"
)

// NewReadSeekCloser returns a seeker to make the HTTP response seekable.
// Callers should ensure that the server supports Range request.
func NewReadSeekCloser(c Client, r *http.Request, respBody io.ReadCloser, size int64) io.ReadSeekCloser {
	return &readSeekCloser{
		client:  c,
		request: r,
		rc:      respBody,
		size:    size,
	}
}

// readSeekCloser seeks http body by starting new connections.
type readSeekCloser struct {
	client  Client
	request *http.Request
	rc      io.ReadCloser
	size    int64

	// lazy initialized and cached properties
	offset int64
	closed bool
}

// Read reads the content body and counts offset.
func (rsc *readSeekCloser) Read(p []byte) (n int, err error) {
	if rsc.closed {
		return 0, errors.New("read: already closed")
	}
	n, err = rsc.rc.Read(p)
	rsc.offset += int64(n)
	return
}

// Seek starts a new connection to the remote for reading if position changes.
func (rsc *readSeekCloser) Seek(offset int64, whence int) (int64, error) {
	if rsc.closed {
		return 0, errors.New("seek: already closed")
	}
	switch whence {
	case io.SeekCurrent:
		offset += rsc.offset
	case io.SeekStart:
		// no-op
	case io.SeekEnd:
		offset += rsc.size
	default:
		return 0, fmt.Errorf("seek: invalid whence %d", whence)
	}
	if offset < 0 {
		return 0, errors.New("seek: an attempt was made to move the pointer before the beginning of the content")
	}
	if offset == rsc.offset {
		return offset, nil
	}
	if offset >= rsc.size {
		xio.CloseAndSkipError(rsc.rc)
		rsc.rc = http.NoBody
		rsc.offset = offset
		return offset, nil
	}

	req := rsc.request.Clone(rsc.request.Context())
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, rsc.size-1))
	resp, err := rsc.client.Do(req) //nolint:bodyclose // closed by xio.CloseAndSkipError() or Close()
	if err != nil {
		return 0, fmt.Errorf("seek: %w", err)
	}
	if err := Success(resp, http.StatusPartialContent); err != nil {
		xio.CloseAndSkipError(resp.Body)
		return 0, fmt.Errorf("seek: %w", err)
	}

	// close and reset internal io.ReadCloser to new response body
	xio.CloseAndSkipError(rsc.rc)
	rsc.rc = resp.Body
	rsc.offset = offset
	return offset, nil
}

// Close closes the internal [io.ReadCloser] response body.
func (rsc *readSeekCloser) Close() error {
	if rsc.closed {
		return nil
	}
	rsc.closed = true
	return rsc.rc.Close()
}

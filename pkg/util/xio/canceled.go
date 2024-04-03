package xio

import (
	"context"
	"io"
)

// NewCanceledReadCloser creates a wrapper that closes the ReadCloser when the
// context is canceled. The returned io.ReadCloser must be closed when it is
// no longer needed.
func NewCanceledReadCloser(ctx context.Context, in io.ReadCloser) io.ReadCloser {
	pR, pW := io.Pipe()

	// Create a context used to signal when the pipe is closed
	doneCtx, cancel := context.WithCancel(context.Background())

	p := &canceledReadCloser{
		cancel: cancel,
		pr:     pR,
		pw:     pW,
	}

	go func() {
		_, err := io.Copy(pW, in)
		select {
		case <-ctx.Done():
			// If the context was closed, p.closeWithError
			// was already called. Calling it again would
			// change the error that Read returns.
		default:
			p.closeWithError(err)
		}
		in.Close()
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				p.closeWithError(ctx.Err())
			case <-doneCtx.Done():
				return
			}
		}
	}()

	return p
}

// canceledReadCloser wraps an io.ReadCloser with a context for canceling read
// operations.
type canceledReadCloser struct {
	cancel func()
	pr     *io.PipeReader // Stream to read from
	pw     *io.PipeWriter
}

// Read wraps the Read method of the pipe that provides data from the wrapped
// ReadCloser.
func (p *canceledReadCloser) Read(buf []byte) (n int, err error) {
	return p.pr.Read(buf)
}

// Close closes the wrapper its underlying reader. It will cause
// future calls to Read to return io.EOF.
func (p *canceledReadCloser) Close() error {
	p.closeWithError(io.EOF)
	return nil
}

// closeWithError closes the wrapper and its underlying reader. It will
// cause future calls to Read to return err.
func (p *canceledReadCloser) closeWithError(err error) {
	p.pw.CloseWithError(err)
	p.cancel()
}

package xio

import "io"

// NopReader returns a [io.ReadCloser] with a no-op Close method wrapping the
// provided [io.Reader] r.
// If r implements [io.WriterTo], the returned [io.ReadCloser] will implement
// [io.WriterTo] by forwarding calls to r.
func NopReader(r io.Reader) io.ReadCloser {
	return io.NopCloser(r)
}

// NopWriter returns a [io.WriteCloser] with a no-op Close method wrapping the
// provided [io.Writer] w.
func NopWriter(w io.Writer) io.WriteCloser {
	return nopWriteCloser{w}
}

type nopWriteCloser struct {
	io.Writer
}

// Close implements [io.Closer] interface.
func (w nopWriteCloser) Close() error {
	return nil
}

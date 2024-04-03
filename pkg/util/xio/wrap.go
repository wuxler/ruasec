package xio

import "io"

// WrapReader wraps an io.Reader with an io.ReadCloser.
//
// It takes an io.Reader and a closer function as parameters.
// The closer function is called when the ReadCloser is closed.
// If the io.Reader implements the io.WriterTo interface,
// it returns a readCloserWriteToWrapper that implements
// both io.Reader and io.ReadCloser. Otherwise, it returns
// a readCloserWrapper that also implements io.ReadCloser.
func WrapReader(r io.Reader, closer func() error) io.ReadCloser {
	if _, ok := r.(io.WriterTo); ok {
		return readCloserWriteToWrapper{r, closer}
	}
	return readCloserWrapper{r, closer}
}

// WrapWriter wraps an io.Writer and a closer function into an io.WriteCloser.
func WrapWriter(w io.Writer, closer func() error) io.WriteCloser {
	return writeCloserWrapper{w, closer}
}

type readCloserWrapper struct {
	io.Reader
	closer func() error
}

func (r readCloserWrapper) Close() error {
	if r.closer != nil {
		return r.closer()
	}
	return nil
}

type readCloserWriteToWrapper struct {
	io.Reader
	closer func() error
}

func (r readCloserWriteToWrapper) WriteTo(w io.Writer) (int64, error) {
	return r.Reader.(io.WriterTo).WriteTo(w)
}

func (r readCloserWriteToWrapper) Close() error {
	if r.closer != nil {
		return r.closer()
	}
	return nil
}

type writeCloserWrapper struct {
	io.Writer
	closer func() error
}

func (w writeCloserWrapper) Close() error {
	if w.closer != nil {
		return w.closer()
	}
	return nil
}

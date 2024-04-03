package xio

import (
	"bytes"
	"io"
)

// NewRewindReader returns a rewindable reader that can be rewound (reset)
// to re-read what was already and then continue to read more from the
// underlying stream.
func NewRewindReader(r io.Reader) *RewindReader {
	if IsNil(r) {
		return nil
	}
	return &RewindReader{
		raw: r,
		buf: new(bytes.Buffer),
	}
}

// RewindReader is a Reader that can be rewound (reset) to re-read what
// was already read and then continue to read more from the underlying
// stream. When no more rewinding is necessary, call Reader() to get a
// new reader that first reads the buffered bytes, then continues to
// read from the stream. This is useful for "peeking" a stream an
// arbitrary number of bytes. Loosely based on the Connection type
// from https://github.com/mholt/caddy-l4.
type RewindReader struct {
	raw       io.Reader
	buf       *bytes.Buffer
	bufReader io.Reader
}

func (rr *RewindReader) Read(p []byte) (n int, err error) {
	if rr == nil {
		panic("internal error: reading from nil RewindReader")
	}
	// if there is a buffer we should read from, start
	// with that; we only read from the underlying stream
	// after the buffer has been "depleted"
	if rr.bufReader != nil {
		n, err = rr.bufReader.Read(p)
		if err == io.EOF {
			rr.bufReader = nil
			err = nil
		}
		if n == len(p) {
			return
		}
	}

	// buffer has been "depleted" so read from
	// underlying connection
	nr, err := rr.raw.Read(p[n:])

	// anything that was read needs to be written to
	// the buffer, even if there was an error
	if nr > 0 {
		if nw, errw := rr.buf.Write(p[n : n+nr]); errw != nil {
			return nw, errw
		}
	}

	// up to now, n was how many bytes were read from
	// the buffer, and nr was how many bytes were read
	// from the stream; add them to return total count
	n += nr

	return
}

// Rewind resets the stream to the beginning by causing
// Read() to start reading from the beginning of the
// buffered bytes.
func (rr *RewindReader) Rewind() {
	if rr == nil {
		return
	}
	rr.bufReader = bytes.NewReader(rr.buf.Bytes())
}

// Reader returns a Reader that reads first from the buffered
// bytes, then from the underlying stream. After calling this,
// no more rewinding is allowed since reads from the stream are
// not recorded, so rewinding properly is impossible.
// If the underlying Reader implements io.Seeker, then the
// underlying Reader will be used directly.
func (rr *RewindReader) Reader() io.Reader {
	if rr == nil {
		return nil
	}
	if ras, ok := rr.raw.(io.Seeker); ok {
		if _, err := ras.Seek(0, io.SeekStart); err == nil {
			return rr.raw
		}
	}
	return io.MultiReader(bytes.NewReader(rr.buf.Bytes()), rr.raw)
}

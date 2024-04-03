package xio

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type perpetualReader struct{}

func (p *perpetualReader) Read(buf []byte) (n int, err error) {
	for i := 0; i != len(buf); i++ {
		buf[i] = 'a'
	}
	return len(buf), nil
}

func TestCancelReadCloser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cancelReadCloser := NewCanceledReadCloser(ctx, io.NopCloser(&perpetualReader{}))
	for {
		var buf [128]byte
		_, err := cancelReadCloser.Read(buf[:])
		if errors.Is(err, context.DeadlineExceeded) {
			break
		} else if err != nil {
			t.Fatalf("got unexpected error: %v", err)
		}
	}
}

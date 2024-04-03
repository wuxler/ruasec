package xio

import (
	"bytes"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapReader(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		closed := false
		r := strings.NewReader("hello world")
		rc := WrapReader(r, func() error {
			closed = true
			return nil
		})
		assert.IsType(t, readCloserWriteToWrapper{}, rc)
		err := rc.Close()
		require.NoError(t, err)
		assert.True(t, closed)
	})

	t.Run("read only", func(t *testing.T) {
		closed := false
		r := iotest.DataErrReader(strings.NewReader("hello world"))
		rc := WrapReader(r, func() error {
			closed = true
			return nil
		})
		assert.IsType(t, readCloserWrapper{}, rc)
		err := rc.Close()
		require.NoError(t, err)
		assert.True(t, closed)
	})
}

func TestWrapWriter(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		closed := false
		w := &bytes.Buffer{}
		wc := WrapWriter(w, func() error {
			closed = true
			return nil
		})
		assert.IsType(t, writeCloserWrapper{}, wc)
		err := wc.Close()
		require.NoError(t, err)
		assert.True(t, closed)
	})
}

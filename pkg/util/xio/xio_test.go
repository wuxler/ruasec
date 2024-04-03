package xio

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsNil(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		assert.True(t, IsNil(nil))
	})
	t.Run("not nil", func(t *testing.T) {
		assert.False(t, IsNil(1))
	})
	t.Run("struct nil", func(t *testing.T) {
		type T struct{}
		var v *T
		assert.True(t, IsNil(v))
	})
}

func TestLimitCopy(t *testing.T) {
	limit := int64(100)

	t.Run("limit exceeded", func(t *testing.T) {
		w := &bytes.Buffer{}
		r := strings.NewReader(strings.Repeat("a", 101))
		err := LimitCopy(w, r, limit)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "size to read limit hit")
	})

	t.Run("limit not exceeded", func(t *testing.T) {
		w := &bytes.Buffer{}
		r := strings.NewReader(strings.Repeat("a", 99))
		err := LimitCopy(w, r, limit)
		assert.NoError(t, err)
	})
}

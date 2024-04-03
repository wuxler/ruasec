package xio

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMeasuredReader(t *testing.T) {
	dummy1 := "This is a dummy string."
	buffer := bytes.NewBufferString(dummy1)
	r := NewMeasuredReader(buffer)

	got, err := io.ReadAll(r)
	require.NoError(t, err)

	if r.Total() != int64(len(dummy1)) {
		t.Errorf("Wrong count: %d vs. %d", r.Total(), len(dummy1))
	}
	assert.Equal(t, dummy1, string(got))
}

func TestMeasuredWriter(t *testing.T) {
	dummy1 := "This is a dummy string."
	dummy2 := "This is another dummy string."
	totalLength := len(dummy1) + len(dummy2)

	reader1 := strings.NewReader(dummy1)
	reader2 := strings.NewReader(dummy2)

	var buffer bytes.Buffer
	w := NewMeasuredWriter(&buffer)

	_, err := reader1.WriteTo(w)
	require.NoError(t, err)
	_, err = reader2.WriteTo(w)
	require.NoError(t, err)

	if w.Total() != int64(totalLength) {
		t.Errorf("Wrong count: %d vs. %d", w.Total(), totalLength)
	}

	if buffer.String() != dummy1+dummy2 {
		t.Error("Wrong message written")
	}
}

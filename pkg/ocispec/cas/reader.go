package cas

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
)

// Reader means the io.Reader is describable.
type Reader interface {
	ocispec.Describable
	io.Reader
}

// ReadCloser means the io.ReadCloser is describable.
type ReadCloser interface {
	Reader
	io.Closer
}

// ReaderGetter is a functional type to get [Reader]
type ReaderGetter func(ctx context.Context) (Reader, error)

// ReadCloserGetter is a functional type to get [ReadCloser]
type ReadCloserGetter func(ctx context.Context) (ReadCloser, error)

// NewReader returns a [Reader] with digest and size veirfication on Read().
func NewReader(r io.Reader, desc imgspecv1.Descriptor) Reader {
	return NewReadCloser(io.NopCloser(r), desc)
}

// NewReaderSkipVerify returns a [Reader] without digest and size veirfication on Read().
func NewReaderSkipVerify(r io.Reader, desc imgspecv1.Descriptor) Reader {
	return NewReadCloserSkipVerify(io.NopCloser(r), desc)
}

// NewReaderFromBytes returns a Reader, given the content and media type.
// If no media type is specified, "application/octet-stream" will be used.
func NewReaderFromBytes(mediaType string, content []byte) Reader {
	desc := ocispec.NewDescriptorFromBytes(mediaType, content)
	return NewReader(bytes.NewReader(content), desc)
}

// NewReadCloser returns a [ReadCloser] with digest and size veirfication on Read().
func NewReadCloser(rc io.ReadCloser, desc imgspecv1.Descriptor) ReadCloser {
	return newVerifyReader(rc, desc, false)
}

// NewReadCloserSkipVerify returns a [ReadCloser] without digest and size verification on Read().
func NewReadCloserSkipVerify(rc io.ReadCloser, desc imgspecv1.Descriptor) ReadCloser {
	return newVerifyReader(rc, desc, true)
}

func newVerifyReader(rc io.ReadCloser, desc imgspecv1.Descriptor, skipVerify bool) *verifyReader {
	digester := desc.Digest.Algorithm().Digester()
	teeReader := io.TeeReader(rc, digester.Hash())
	drc := &verifyReader{
		ReadCloser: rc,
		desc:       desc,
		skipVerify: skipVerify,
		digester:   digester,
		teeReader:  teeReader,
	}
	return drc
}

type verifyReader struct {
	io.ReadCloser
	desc       imgspecv1.Descriptor
	skipVerify bool
	digester   digest.Digester
	teeReader  io.Reader

	n int64
}

// Descriptor returns the descriptor for the resource.
func (drc *verifyReader) Descriptor() imgspecv1.Descriptor {
	return drc.desc
}

func (drc *verifyReader) Read(p []byte) (int, error) {
	n, err := drc.teeReader.Read(p)
	drc.n += int64(n)
	if err == nil {
		if drc.n > drc.desc.Size {
			// Fail early when the manifest or blob is too big; we can do that even
			// when we're not verifying for other use cases.
			// TODO(wuxler): wrap standard errors with a more specific error type
			return n, fmt.Errorf("size exceeds content length %d", drc.desc.Size)
		}
		return n, nil
	}
	if err != io.EOF {
		return n, err
	}
	// at EOF, check should we verify the digest
	if drc.skipVerify {
		return n, err
	}
	if drc.n != drc.desc.Size {
		// TODO(wuxler): wrap standard errors with a more specific error type
		return n, fmt.Errorf("size mismatch (%d != %d)", drc.n, drc.desc.Size)
	}
	got := drc.digester.Digest()
	if got != drc.desc.Digest {
		// TODO(wuxler): wrap standard errors with a more specific error type
		return n, fmt.Errorf("digest mismatch (%s != %s)", got, drc.desc.Digest)
	}
	return n, err
}

func (drc *verifyReader) Close() error {
	return drc.ReadCloser.Close()
}

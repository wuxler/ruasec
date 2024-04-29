package distribution

import (
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Describable defines a registry resource that can be described.
type Describable interface {
	// Descriptor returns the descriptor for the resource.
	Descriptor() v1.Descriptor
}

// DescribableReadCloser provides the contents of a given blob or manifest.
type DescribableReadCloser interface {
	Describable
	io.ReadCloser
}

// NewDescribableReadCloser returns a DescribableReadCloser with the descriptor.
func NewDescribableReadCloser(rc io.ReadCloser, desc v1.Descriptor) DescribableReadCloser {
	return newDescribableReadCloser(rc, desc, false)
}

// NewDescribableReadCloserSkipVerify returns a DescribableReadCloser with skip
// digest and size verification on Read().
func NewDescribableReadCloserSkipVerify(rc io.ReadCloser, desc v1.Descriptor) DescribableReadCloser {
	return newDescribableReadCloser(rc, desc, true)
}

func newDescribableReadCloser(rc io.ReadCloser, desc v1.Descriptor, skipVerify bool) *describableReadCloser {
	digester := desc.Digest.Algorithm().Digester()
	teeReader := io.TeeReader(rc, digester.Hash())
	drc := &describableReadCloser{
		rc:         rc,
		desc:       desc,
		skipVerify: skipVerify,
		digester:   digester,
		teeReader:  teeReader,
	}
	return drc
}

type describableReadCloser struct {
	rc         io.ReadCloser
	desc       v1.Descriptor
	skipVerify bool
	digester   digest.Digester
	teeReader  io.Reader

	n int64
}

// Descriptor returns the descriptor for the resource.
func (drc *describableReadCloser) Descriptor() v1.Descriptor {
	return drc.desc
}

func (drc *describableReadCloser) Read(p []byte) (int, error) {
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

func (drc *describableReadCloser) Close() error {
	return drc.rc.Close()
}

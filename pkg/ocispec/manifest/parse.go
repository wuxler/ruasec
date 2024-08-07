package manifest

import (
	"io"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
)

// Parse parses manifest bytes with expect media type applied. Returns error if
// schema is not found in registers.
func Parse(mediaType string, content []byte) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	unmarshalFunc, err := GetSchema(mediaType)
	if err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	return unmarshalFunc(content)
}

// ParseBytes parses manifest bytes with no media type specified, will try
// to detect media type first before parsing.
func ParseBytes(content []byte) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	mt := ocispec.DetectMediaType(content)
	m, desc, err := Parse(mt, content)
	if err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	return m, desc, nil
}

// ParseCASReader parses manifest from a CAS Reader applied.
func ParseCASReader(r cas.Reader) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	desc := r.Descriptor()
	m, _, err := Parse(desc.MediaType, content)
	if err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	return m, desc, nil
}

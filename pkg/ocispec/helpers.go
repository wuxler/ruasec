package ocispec

import (
	"github.com/containers/libtrust"
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Digest returns the a digest of a docker manifest, with any necessary implied
// transformations like stripping v1s1 signatures.
func Digest(content []byte) (digest.Digest, error) {
	mt := DetectMediaType(content)
	if mt == MediaTypeDockerV2S1SignedManifest {
		sig, err := libtrust.ParsePrettySignature(content, "signatures")
		if err != nil {
			return "", err
		}
		content, err = sig.Payload()
		if err != nil {
			// Coverage: This should never happen, libtrust's Payload() can fail
			// only if joseBase64UrlDecode() fails, on a string that libtrust itself
			// has josebase64UrlEncode()
			return "", err
		}
	}
	return digest.FromBytes(content), nil
}

// MatchesDigest returns true if the manifest matches expectedDigest.
// Error may be set if this returns false.
func MatchesDigest(content []byte, expectedDigest digest.Digest) (bool, error) {
	// This should eventually support various digest types.
	actualDigest, err := Digest(content)
	if err != nil {
		return false, err
	}
	return expectedDigest == actualDigest, nil
}

// NewDescriptorFromBytes returns a descriptor, given the content and media type.
// If no media type is specified, "application/octet-stream" will be used.
func NewDescriptorFromBytes(mediaType string, content []byte) imgspecv1.Descriptor {
	if mediaType == "" {
		mediaType = DefaultMediaType
	}
	return imgspecv1.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(content),
		Size:      int64(len(content)),
	}
}

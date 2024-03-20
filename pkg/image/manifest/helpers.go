package manifest

import (
	"encoding/json"

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

// DetectMediaType 推测 []byte 对应的 manifest 类型并返回对应的 media type,
// 如果类型未知或者未识别, 返回空字符串.
//
// NOTE: 通常, 我们应该直接在外部获取到 media type 而不是通过解析的方式推测, 但是
// 可能存在无法在外部获取到 manifest 的 media type 情况，如 manifest 是一个本地
// 文件.
func DetectMediaType(content []byte) string {
	// A subset of manifest fields; the rest is silently ignored by json.Unmarshal.
	// Also docker/distribution/manifest.Versioned.
	meta := struct {
		MediaType     string      `json:"mediaType"`
		SchemaVersion int         `json:"schemaVersion"`
		Signatures    interface{} `json:"signatures"`
	}{}
	if err := json.Unmarshal(content, &meta); err != nil {
		return ""
	}

	switch meta.MediaType {
	case MediaTypeDockerV2S2Manifest, MediaTypeDockerV2S2ManifestList,
		MediaTypeImageManifest, MediaTypeImageIndex: // A recognized type.
		return meta.MediaType
	}

	// this is the only way the function can return DockerV2Schema1MediaType,
	// and recognizing that is essential for stripping the JWS signatures = computing
	// the correct manifest digest.
	switch meta.SchemaVersion {
	case 1:
		if meta.Signatures != nil {
			return MediaTypeDockerV2S1SignedManifest
		}
		return MediaTypeDockerV2S1Manifest
	case 2: //nolint:gomnd // skip magic number check
		// Best effort to understand if this is an OCI image since mediaType
		// wasn't in the manifest for OCI image-spec < 1.0.2.
		// For docker v2s2 meta.MediaType should have been set. But given the data,
		// this is our best guess.
		ociManifest := struct {
			Config struct {
				MediaType string `json:"mediaType"`
			} `json:"config"`
		}{}
		if err := json.Unmarshal(content, &ociManifest); err != nil {
			return ""
		}
		switch ociManifest.Config.MediaType {
		case MediaTypeImageConfig:
			return MediaTypeImageManifest
		case MediaTypeDockerV2S2ImageConfig:
			// This case should not happen since a Docker image must declare
			// a top-level media type and `meta.MediaType` has already been checked.
			return MediaTypeDockerV2S2Manifest
		}
		// Maybe an image index or an OCI artifact.
		ociIndex := struct {
			Manifests []imgspecv1.Descriptor `json:"manifests"`
		}{}
		if err := json.Unmarshal(content, &ociIndex); err != nil {
			return ""
		}
		if len(ociIndex.Manifests) != 0 {
			if ociManifest.Config.MediaType == "" {
				return MediaTypeImageIndex
			}
			// FIXME: this is mixing media types of manifests and configs.
			return ociManifest.Config.MediaType
		}
		// It's most likely an OCI artifact with a custom config media
		// type which is not (and cannot) be covered by the media-type
		// checks cabove.
		return MediaTypeImageManifest
	}
	return ""
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

// NonEmptyLayers filters out empty layer descriptors. Main to skip empty blobs in
// docker v2 schema1 manifest.
func NonEmptyLayers(descriptors ...LayerDescriptor) []LayerDescriptor {
	clean := []LayerDescriptor{}
	for i := range descriptors {
		if descriptors[i].Empty {
			continue
		}
		clean = append(clean, descriptors[i])
	}
	return clean
}

// ImageSize sums all layer blobs size as the image compressed size.
func ImageSize(m ImageManifest) int64 {
	var size int64
	layers := NonEmptyLayers(m.Layers()...)
	for i := range layers {
		if layers[i].Size < 0 {
			continue
		}
		size += layers[i].Size
	}
	return size
}

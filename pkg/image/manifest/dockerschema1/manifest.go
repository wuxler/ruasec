package dockerschema1

import (
	"encoding/json"
	"regexp"
	"slices"

	"github.com/containers/libtrust"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

var (
	_ manifest.ImageManifest = (*SignedManifest)(nil)
)

// SignedManifest provides an envelope for a signed image manifest, including
// the format sensitive raw bytes.
//
// Deprecated: Docker Image Manifest v2, Schema 1 is deprecated since 2015.
// Use Docker Image Manifest v2, Schema 2, or the OCI Image Specification.
type SignedManifest struct {
	Manifest

	// Canonical is the canonical byte representation of the ImageManifest,
	// without any attached signatures. The manifest byte
	// representation cannot change or it will have to be re-signed.
	Canonical []byte `json:"-"`

	// ExtractedV1Compatibility is the V1Compatibility parsed from History.
	//
	// NOTE: Keep this in sync with History! Does not contain the full image
	// config (Schema2V1Image)
	ExtractedV1Compatibility []V1Compatibility `json:"-"`

	// all contains the byte representation of the Manifest including signatures
	// and is returned by Payload()
	all []byte
}

// MediaType returns the media type of current manifest object.
func (m SignedManifest) MediaType() string {
	return m.Versioned.MediaType
}

// References returns the descriptors of this manifests references.
func (m SignedManifest) References() []imgspecv1.Descriptor {
	dependencies := make([]imgspecv1.Descriptor, len(m.FSLayers))
	for i, fsLayer := range m.FSLayers {
		dependencies[i] = imgspecv1.Descriptor{
			MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
			Digest:    fsLayer.BlobSum,
		}
	}

	return dependencies
}

// Config returns a descriptor of the separate image config blob.
func (m SignedManifest) Config() imgspecv1.Descriptor {
	return imgspecv1.Descriptor{}
}

// Layers returns a list of LayerDescriptors of layers referenced by the image.
// Ordered from the root layer first (oldest) to the top layer at last (latest).
func (m SignedManifest) Layers() []manifest.LayerDescriptor {
	layers := make([]manifest.LayerDescriptor, len(m.FSLayers))
	for i, layer := range m.FSLayers {
		// NOTE: This includes empty layers (where m.History.V1Compatibility->ThrowAway)
		layers[(len(m.FSLayers)-1)-i] = manifest.LayerDescriptor{
			Descriptor: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
				Digest:    layer.BlobSum,
				Size:      -1,
			},
			Empty: m.ExtractedV1Compatibility[i].ThrowAway,
		}
	}
	return layers
}

// UnmarshalJSON populates a new SignedManifest struct from JSON data.
func (m *SignedManifest) UnmarshalJSON(b []byte) error {
	m.all = make([]byte, len(b))
	// store manifest and signatures in all
	copy(m.all, b)

	jsig, err := libtrust.ParsePrettySignature(b, "signatures")
	if err != nil {
		return err
	}

	// Resolve the payload in the manifest.
	bytes, err := jsig.Payload()
	if err != nil {
		return err
	}

	// m.Canonical stores the canonical manifest JSON
	m.Canonical = make([]byte, len(bytes))
	copy(m.Canonical, bytes)

	// Unmarshal canonical JSON into Manifest object
	var mfst Manifest
	if err := json.Unmarshal(m.Canonical, &mfst); err != nil {
		return err
	}

	if len(mfst.History) != len(mfst.FSLayers) {
		return manifest.NewErrInvalidField(
			"length of history not equal to number of fsLayers: %d != %d",
			len(mfst.History), len(mfst.FSLayers))
	}
	if len(mfst.FSLayers) == 0 {
		return manifest.NewErrInvalidField("no fsLayers in manifest")
	}

	m.ExtractedV1Compatibility = make([]V1Compatibility, len(mfst.History))
	for i, h := range mfst.History {
		//nolint:musttag // we're not using the struct tags here
		if err := json.Unmarshal([]byte(h.V1Compatibility), &m.ExtractedV1Compatibility[i]); err != nil {
			return manifest.NewErrInvalidField(
				"parsing docker v2 schema1 history entry %d error: %w", i, err)
		}
	}
	m.Manifest = mfst

	return m.fixManifestLayers()
}

var validHex = regexp.MustCompile(`^([a-f0-9]{64})$`)

func validateV1ID(id string) error {
	if ok := validHex.MatchString(id); !ok {
		return manifest.NewErrInvalidField("image ID %q is invalid", id)
	}
	return nil
}

// fixManifestLayers, after validating the supplied manifest
// (to use correctly-formatted IDs, and to not have non-consecutive ID collisions in m.History),
// modifies manifest to only have one entry for each layer ID in m.History (deleting the older duplicates,
// both from m.History and m.FSLayers).
//
// NOTE: even after this succeeds, m.FSLayers may contain duplicate entries
// (for Dockerfile operations which change the configuration but not the filesystem).
func (m *SignedManifest) fixManifestLayers() error {
	// m.UnmarshalJSON() has already verified that len(m.FSLayers) == len(m.History)
	for _, compat := range m.ExtractedV1Compatibility {
		if err := validateV1ID(compat.ID); err != nil {
			return err
		}
	}
	if m.ExtractedV1Compatibility[len(m.ExtractedV1Compatibility)-1].Parent != "" {
		return manifest.NewErrInvalidField("invalid parent ID in the base layer of the image")
	}
	// check general duplicates to error instead of a deadlock
	idmap := make(map[string]struct{})
	var lastID string
	for _, img := range m.ExtractedV1Compatibility {
		// skip IDs that appear after each other, we handle those later
		if _, exists := idmap[img.ID]; img.ID != lastID && exists {
			return manifest.NewErrInvalidField("ID %+v appears multiple times in manifest", img.ID)
		}
		lastID = img.ID
		idmap[lastID] = struct{}{}
	}
	// backwards loop so that we keep the remaining indexes after removing items
	for i := len(m.ExtractedV1Compatibility) - 2; i >= 0; i-- {
		if m.ExtractedV1Compatibility[i].ID == m.ExtractedV1Compatibility[i+1].ID {
			// repeated ID, remove and continue
			m.FSLayers = slices.Delete(m.FSLayers, i, i+1)
			m.History = slices.Delete(m.History, i, i+1)
			m.ExtractedV1Compatibility = slices.Delete(m.ExtractedV1Compatibility, i, i+1)
		} else if m.ExtractedV1Compatibility[i].Parent != m.ExtractedV1Compatibility[i+1].ID {
			return manifest.NewErrInvalidField("invalid parent ID expected %v, but got %v",
				m.ExtractedV1Compatibility[i+1].ID, m.ExtractedV1Compatibility[i].Parent)
		}
	}
	return nil
}

// MarshalJSON returns the contents of raw. If Raw is nil, marshals the inner
// contents. Applications requiring a marshaled signed manifest should simply
// use Raw directly, since the the content produced by json.Marshal will be
// compacted and will fail signature checks.
func (m *SignedManifest) MarshalJSON() ([]byte, error) {
	if len(m.all) > 0 {
		return m.all, nil
	}

	// If the raw data is not available, just dump the inner content.
	return json.Marshal(&m.Manifest)
}

// Payload returns the signed content of the signed manifest.
func (m SignedManifest) Payload() ([]byte, error) {
	return m.all, nil
}

// Signatures returns the signatures as provided by
// (*libtrust.JSONSignature).Signatures. The byte slices are opaque jws
// signatures.
func (m *SignedManifest) Signatures() ([][]byte, error) {
	jsig, err := libtrust.ParsePrettySignature(m.all, "signatures")
	if err != nil {
		return nil, err
	}

	// Resolve the payload in the manifest.
	return jsig.Signatures()
}

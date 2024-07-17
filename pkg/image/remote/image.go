package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/opencontainers/image-spec/identity"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/xlog"
)

var _ ocispec.ImageCloser = (*remoteImage)(nil)

// NewImageByRef creates a new image specified by the string ref and context.
func NewImageByRef(ctx context.Context, client *remote.Registry, ref string, opts ...image.QueryOption) (ocispec.ImageCloser, error) {
	name, err := ocispecname.NewReference(ref)
	if err != nil {
		return nil, err
	}
	img, err := NewImage(ctx, client, name, opts...)
	if err != nil {
		return nil, err
	}
	raw, ok := img.(*remoteImage)
	if !ok {
		return nil, fmt.Errorf("unexpected image type %T", img)
	}
	raw.metadata.Name = ref
	return raw, nil
}

// NewImage creates a new image speicified by the parsed name and context.
//
//nolint:nolintlint,gocognit // ignore explicitly
func NewImage(ctx context.Context, client *remote.Registry, ref ocispecname.Reference, opts ...image.QueryOption) (ocispec.ImageCloser, error) {
	options := image.MakeQueryOptions(opts...)

	// check if the reference is in the registry
	expectHostname := client.Name().Hostname()
	if ref.Repository().Domain().Hostname() != expectHostname {
		return nil, fmt.Errorf("target reference %q seems not in the registry %q", ref, expectHostname)
	}
	// get repository client for the reference
	repo := client.Repository(ref.Repository().Path())
	img := &remoteImage{
		client: repo,
		name:   ref,
	}
	tagOrDigest, err := ocispecname.Identify(ref)
	if err != nil {
		return nil, err
	}
	// fetch the manifest of the reference
	rc, err := repo.Manifests().FetchTagOrDigest(ctx, tagOrDigest)
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(rc)

	m, desc, err := manifest.ParseCASReader(rc)
	if err != nil {
		return nil, err
	}

	isIndexManifest := false
	switch mn := m.(type) {
	case ocispec.IndexManifest:
		// select and fetch the speicified instance image manifest by the query options
		matchers := []manifest.DescriptorMatcher{}
		if options.InstanceDigest != "" {
			matchers = append(matchers, manifest.DescriptorMatcherByDigest(options.InstanceDigest))
		}
		matchers = append(matchers, manifest.DescriptorMatcherByPlatform(options.Platform))
		selectedManifest, selectedDesc, err := manifest.SelectManifest(
			ctx, repo.Manifests(), mn, matchers...)
		if err != nil {
			return nil, err
		}
		imageManifest, ok := selectedManifest.(manifest.ImageManifest)
		if !ok {
			return nil, fmt.Errorf("unexpected manifest type %T", selectedManifest)
		}
		img.manifest = imageManifest
		img.descriptor = selectedDesc
		isIndexManifest = true
	case manifest.ImageManifest:
		img.manifest = mn
		img.descriptor = desc
	default:
		return nil, errdefs.Newf(errdefs.ErrUnsupported, "unsupported manifest type %T", m)
	}

	// TODO: convert docker schema1 manifest to *ocispecv1.Image config
	if mt := img.manifest.MediaType(); ocispec.IsDockerSchema1Manifest(mt) {
		return nil, errdefs.Newf(errdefs.ErrUnsupported, "docker scheme1 manifest %q is unsupported", mt)
	}

	// create the image metadata
	metadata := ocispec.ImageMetadata{
		ID:       img.manifest.Config().Digest,
		Digest:   img.descriptor.Digest,
		Name:     ref.String(),
		Platform: img.descriptor.Platform,
	}

	if isIndexManifest {
		metadata.IndexDigest = desc.Digest
	}

	// check if layers of the image is compressed and set image compressed/uncompressed size
	isCompressed := false
	layers := img.manifest.Layers()
	for i := range layers {
		if !layers[i].Empty && ocispec.IsCompressedBlob(layers[i].MediaType) {
			isCompressed = true
		}
	}
	metadata.IsCompressed = isCompressed
	size := manifest.ImageSize(img.manifest)
	if isCompressed {
		metadata.CompressedSize = size
	} else {
		metadata.UncompressedSize = size
	}

	img.metadata.RepoDigests = append(img.metadata.RepoDigests,
		ocispecname.MustWithDigest(ref.Repository(), metadata.Digest).String())
	if tagged, ok := ocispecname.IsTagged(ref); ok {
		img.metadata.RepoTags = append(img.metadata.RepoTags,
			ocispecname.MustWithTag(ref.Repository(), tagged.Tag()).String())
	}

	img.metadata = metadata
	return img, nil
}

type remoteImage struct {
	client     *remote.Repository
	name       ocispecname.Reference
	manifest   manifest.ImageManifest
	descriptor imgspecv1.Descriptor
	metadata   ocispec.ImageMetadata

	// lazy initialized and cached properties
	configFileContent []byte
	layers            []*remoteLayer
}

// Metadata returns the metadata of the image.
func (img *remoteImage) Metadata() ocispec.ImageMetadata {
	return img.metadata
}

// ConfigFile returns the image config.
func (img *remoteImage) ConfigFile(ctx context.Context) ([]byte, error) {
	if img.configFileContent != nil {
		return img.configFileContent, nil
	}

	desc := img.manifest.Config()
	rc, err := img.client.Blobs().Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(rc)

	content, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	img.configFileContent = content

	img.configFileContent = content
	return img.configFileContent, nil
}

// Layers returns a list of layer objects contained in the current image in order.
// The list order is from the oldest/base layer to the most-recent/top layer.
func (img *remoteImage) Layers(ctx context.Context) ([]ocispec.Layer, error) {
	if img.layers != nil {
		return toLayers(img.layers), nil
	}

	// fetch and parse image config file
	configFile, err := img.ConfigFile(ctx)
	if err != nil {
		return nil, err
	}
	config := &imgspecv1.Image{}
	if err := json.Unmarshal(configFile, config); err != nil {
		return nil, err
	}

	// validate layers infos
	diffids := config.RootFS.DiffIDs
	if len(diffids) == 0 {
		return nil, errdefs.Newf(errdefs.ErrUnsupported, "no DiffIDs found in image config")
	}
	chainids := identity.ChainIDs(slices.Clone(diffids))
	if len(diffids) != len(chainids) {
		return nil, fmt.Errorf("mismatch length of DiffIDs and ChainIDs: %d != %d", len(diffids), len(chainids))
	}
	descriptors := manifest.NonEmptyLayers(img.manifest.Layers()...)
	if len(diffids) != len(descriptors) {
		return nil, fmt.Errorf("mismatch length of DiffIDs and Descriptors: %d != %d", len(diffids), len(descriptors))
	}

	var parent *remoteLayer
	var layers []*remoteLayer
	for i, diffid := range diffids {
		desc := descriptors[i]
		metadata := ocispec.LayerMetadata{
			DiffID:       diffid,
			ChainID:      chainids[i],
			Parent:       parent,
			IsCompressed: ocispec.IsCompressedBlob(desc.MediaType),
		}
		if metadata.IsCompressed {
			metadata.CompressedSize = desc.Size
		} else {
			metadata.UncompressedSize = desc.Size
		}
		current := &remoteLayer{
			client:     img.client,
			metadata:   metadata,
			descriptor: desc.Descriptor,
		}
		parent = current
		layers = append(layers, current)
	}

	histories := []imgspecv1.History{}
	for _, history := range config.History {
		if !history.EmptyLayer {
			histories = append(histories, history)
		}
	}
	if len(layers) != len(histories) {
		xlog.C(ctx).Warnf("skip, mismatch length of layers and non-empty hisotries: %d != %d", len(diffids), len(histories))
	} else {
		for i, layer := range layers {
			layer.metadata.History = &histories[i]
		}
	}

	img.layers = layers
	return toLayers(img.layers), nil
}

// Close releases any resources associated with the image.
func (img *remoteImage) Close() error {
	return nil
}

// Descriptor returns the descriptor for the resource.
func (img *remoteImage) Descriptor() imgspecv1.Descriptor {
	return img.descriptor
}

// Package remote provides remote type image implementations and operations.
package remote

import (
	"context"
	"fmt"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/all"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

var _ image.Storage = (*Storage)(nil)

func init() {
	ocispecname.RegisterScheme(image.StorageTypeRemote)
	ocispecname.RegisterScheme("http")
	ocispecname.RegisterScheme("https")
}

// NewStorage returns a remote type storage.
func NewStorage(client *remote.Registry) *Storage {
	return &Storage{client: client}
}

// Storage is a wrapper for remote registry implements Storage interface.
type Storage struct {
	client *remote.Registry
}

// Type returns the unique identity type of the provider.
func (p *Storage) Type() string {
	return image.StorageTypeRemote
}

// Image returns the image specified by the ref.
func (p *Storage) GetImage(ctx context.Context, ref ocispecname.Reference, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	client := p.client
	options := image.MakeImageOptions(opts...)

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

	mf, desc, err := manifest.ParseCASReader(rc)
	if err != nil {
		return nil, err
	}

	// select the manifest and descriptor of the target image
	selectedManifest, selectedDesc, err := manifest.SelectImageManifest(
		ctx, repo.Manifests(), mf, desc, options.DescriptorMatchers()...)
	if err != nil {
		return nil, err
	}
	img.manifest = selectedManifest
	img.descriptor = selectedDesc

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

	if _, isIndexManifest := mf.(ocispec.IndexManifest); isIndexManifest {
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

	metadata.RepoDigests = append(metadata.RepoDigests,
		ocispecname.MustWithDigest(ref.Repository(), metadata.Digest).String())
	if tagged, ok := ocispecname.IsTagged(ref); ok {
		metadata.RepoTags = append(metadata.RepoTags,
			ocispecname.MustWithTag(ref.Repository(), tagged.Tag()).String())
	}
	options.ApplyMetadata(&metadata)

	img.metadata = metadata
	return img, nil
}

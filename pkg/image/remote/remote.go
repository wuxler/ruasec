// Package remote provides remote type image implementations and operations.
package remote

import (
	"context"

	"github.com/puzpuzpuz/xsync/v3"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/all"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	ocispecremote "github.com/wuxler/ruasec/pkg/ocispec/remote"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

var _ image.Storage = (*Storage)(nil)

func init() {
	ocispecname.RegisterScheme(image.StorageTypeRemote)
	ocispecname.RegisterScheme("http")
	ocispecname.RegisterScheme("https")
}

// NewStorage returns a remote type storage.
func NewStorage(client *ocispecremote.Client) *Storage {
	return &Storage{
		client:     client,
		registries: xsync.NewMapOf[string, *remote.Registry](),
	}
}

// Storage is a wrapper for remote registry implements Storage interface.
type Storage struct {
	client     *ocispecremote.Client
	registries *xsync.MapOf[string, *remote.Registry]
}

// Type returns the unique identity type of the provider.
func (p *Storage) Type() string {
	return image.StorageTypeRemote
}

// Image returns the image specified by the ref.
func (p *Storage) GetImage(ctx context.Context, ref string, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	options := image.MakeImageOptions(opts...)

	parsedRef, err := ocispecname.NewReference(ref)
	if err != nil {
		return nil, err
	}

	domain := parsedRef.Repository().Domain()
	client, ok := p.registries.Load(domain.Hostname())
	if !ok {
		client, err = remote.NewRegistry(ctx, domain, remote.WithHTTPClient(p.client))
		if err != nil {
			return nil, err
		}
		p.registries.Store(domain.Hostname(), client)
	}

	// get repository client for the reference
	repo := client.Repository(parsedRef.Repository().Path())
	img := &remoteImage{
		client: repo,
		name:   parsedRef,
	}
	tagOrDigest, err := ocispecname.Identify(parsedRef)
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
		Name:     parsedRef.String(),
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
		ocispecname.MustWithDigest(parsedRef.Repository(), metadata.Digest).String())
	if tagged, ok := ocispecname.IsTagged(parsedRef); ok {
		metadata.RepoTags = append(metadata.RepoTags,
			ocispecname.MustWithTag(parsedRef.Repository(), tagged.Tag()).String())
	}
	options.ApplyMetadata(&metadata)

	img.metadata = metadata
	return img, nil
}

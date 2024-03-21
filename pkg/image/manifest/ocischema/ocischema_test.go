package ocischema_test

import (
	"os"
	"path/filepath"
	"testing"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/image/manifest"
	"github.com/wuxler/ruasec/pkg/image/manifest/ocischema"
)

func TestUnmarshalImageManifest(t *testing.T) {
	testcases := []struct {
		input      string
		desc       imgspecv1.Descriptor
		references []imgspecv1.Descriptor
		wantErr    bool
	}{
		{
			input: "ociv1.manifest.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeImageManifest,
				Size:      951,
				Digest:    "sha256:bb76e395cb9021fd062b352172ac87ca159b3e84f5a5758a69db824da876cd4f",
			},
			references: []imgspecv1.Descriptor{
				// config
				{
					MediaType: manifest.MediaTypeImageConfig,
					Size:      7023,
					Digest:    "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
				},
				// layers
				{
					MediaType: manifest.MediaTypeImageLayerGzip,
					Size:      32654,
					Digest:    "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
				},
				{
					MediaType: manifest.MediaTypeImageLayerGzip,
					Size:      16724,
					Digest:    "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
				},
				{
					MediaType: manifest.MediaTypeImageLayerGzip,
					Size:      73109,
					Digest:    "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
				},
			},
		},
		{
			input: "ociv1nomime.manifest.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeImageManifest,
				Size:      890,
				Digest:    "sha256:f94f91aaa4bfad8e67ef7f5cde3a0e908bd22e758868ca47227e60a8ea623d1c",
			},
			references: []imgspecv1.Descriptor{
				// config
				{
					MediaType: manifest.MediaTypeImageConfig,
					Size:      7023,
					Digest:    "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
				},
				// layers
				{
					MediaType: manifest.MediaTypeImageLayerGzip,
					Size:      32654,
					Digest:    "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
				},
				{
					MediaType: manifest.MediaTypeImageLayerGzip,
					Size:      16724,
					Digest:    "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
				},
				{
					MediaType: manifest.MediaTypeImageLayerGzip,
					Size:      73109,
					Digest:    "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
				},
			},
		},
		{
			input: "ociv1.artifact.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeImageManifest,
				Size:      226,
				Digest:    "sha256:ec7d9117f157e92a0fa93de1c9ad07fd8e193dca520684b0a5d67f4f73cd03a0",
			},
			references: []imgspecv1.Descriptor{
				{
					MediaType: "application/vnd.oci.custom.artifact.config.v1+json",
				},
			},
		},
		{
			input: "ociv1nomime.artifact.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeImageManifest,
				Size:      165,
				Digest:    "sha256:d33c74c6e3aacaff74a6a22f22b2e5e6a04b120546a910d320fc6ba033136db8",
			},
			references: []imgspecv1.Descriptor{
				{
					MediaType: "application/vnd.oci.custom.artifact.config.v1+json",
				},
			},
		},
		{
			input:   "ociv1.image.index.json",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("..", "testdata", tc.input))
			require.NoError(t, err)
			mnft, desc, err := ocischema.UnmarshalImageManifest(content)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.desc, desc)
			assert.Equal(t, tc.references, mnft.References())

			payload, err := mnft.Payload()
			require.NoError(t, err)
			assert.Equal(t, content, payload)

			imgmnft, ok := mnft.(manifest.ImageManifest)
			require.True(t, ok)
			config := imgmnft.Config()
			layers := []imgspecv1.Descriptor{}
			for _, d := range manifest.NonEmptyLayers(imgmnft.Layers()...) {
				layers = append(layers, d.Descriptor)
			}
			assert.Equal(t, tc.references[0], config)
			assert.Equal(t, tc.references[1:], layers)
		})
	}
}

func TestUnmarshalIndexManifest(t *testing.T) {
	testcases := []struct {
		input      string
		desc       imgspecv1.Descriptor
		references []imgspecv1.Descriptor
		wantErr    bool
	}{
		{
			input: "ociv1.image.index.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeImageIndex,
				Size:      794,
				Digest:    "sha256:d59976e8b293d743edfd0d9f985207acd97bcca66cb27506bc6e974af13f729e",
			},
			references: []imgspecv1.Descriptor{
				{
					MediaType: manifest.MediaTypeImageManifest,
					Size:      7143,
					Digest:    "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
					Platform: &imgspecv1.Platform{
						Architecture: "ppc64le",
						OS:           "linux",
					},
				},
				{
					MediaType: manifest.MediaTypeImageManifest,
					Size:      7682,
					Digest:    "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
					Platform: &imgspecv1.Platform{
						Architecture: "amd64",
						OS:           "linux",
						OSFeatures: []string{
							"sse4",
						},
					},
				},
			},
		},
		{
			input: "ociv1nomime.image.index.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeImageIndex,
				Size:      736,
				Digest:    "sha256:e23eee643694928ed2881e2bce25afd051cb2c8d2f0cbd46fb9f5e8e84ba23eb",
			},
			references: []imgspecv1.Descriptor{
				{
					MediaType: manifest.MediaTypeImageManifest,
					Size:      7143,
					Digest:    "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
					Platform: &imgspecv1.Platform{
						Architecture: "ppc64le",
						OS:           "linux",
					},
				},
				{
					MediaType: manifest.MediaTypeImageManifest,
					Size:      7682,
					Digest:    "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
					Platform: &imgspecv1.Platform{
						Architecture: "amd64",
						OS:           "linux",
						OSFeatures: []string{
							"sse4",
						},
					},
				},
			},
		},
		{
			input:   "ociv1.manifest.json",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("..", "testdata", tc.input))
			require.NoError(t, err)
			mnft, desc, err := ocischema.UnmarshalIndexManifest(content)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.desc, desc)
			assert.Equal(t, tc.references, mnft.References())

			payload, err := mnft.Payload()
			require.NoError(t, err)
			assert.Equal(t, content, payload)

			indexmnft, ok := mnft.(manifest.IndexManifest)
			require.True(t, ok)
			mnfts := indexmnft.Manifests()
			assert.Equal(t, tc.references, mnfts)
		})
	}
}

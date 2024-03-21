package dockerschema2_test

import (
	"os"
	"path/filepath"
	"testing"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/image/manifest"
	"github.com/wuxler/ruasec/pkg/image/manifest/dockerschema2"
)

func TestUnmarshalImageManifest(t *testing.T) {
	testcases := []struct {
		input      string
		desc       imgspecv1.Descriptor
		references []imgspecv1.Descriptor
		wantErr    bool
	}{
		{
			input: "v2s2.manifest.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S2Manifest,
				Size:      995,
				Digest:    "sha256:20bf21ed457b390829cdbeec8795a7bea1626991fda603e0d01b4e7f60427e55",
			},
			references: []imgspecv1.Descriptor{
				// config
				{
					MediaType: manifest.MediaTypeDockerV2S2ImageConfig,
					Size:      7023,
					Digest:    "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
				},
				// layers
				{
					MediaType: manifest.MediaTypeDockerV2S2ImageLayerGzip,
					Size:      32654,
					Digest:    "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
				},
				{
					MediaType: manifest.MediaTypeDockerV2S2ImageLayerGzip,
					Size:      16724,
					Digest:    "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
				},
				{
					MediaType: manifest.MediaTypeDockerV2S2ImageLayerGzip,
					Size:      73109,
					Digest:    "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
				},
			},
		},
		{
			input: "v2s2.manifest.nomime.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S2Manifest,
				Size:      258,
				Digest:    "sha256:e7648e3307f0760138714bf63f73985c2ead2ed30ec7000378553e8be3d3f207",
			},
			references: []imgspecv1.Descriptor{
				{
					MediaType: "application/vnd.docker.container.image.v1+json",
					Size:      7023,
					Digest:    "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
				},
			},
		},
		{
			input: "ociv1.artifact.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S2Manifest,
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
			input: "ociv1.artifact.nomime.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S2Manifest,
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
			input:   "v2s2.manifest.list.json",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("..", "testdata", tc.input))
			require.NoError(t, err)
			mnft, desc, err := dockerschema2.UnmarshalImageManifest(content)
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

func TestUnmarshalManifestList(t *testing.T) {
	testcases := []struct {
		input      string
		desc       imgspecv1.Descriptor
		references []imgspecv1.Descriptor
		wantErr    bool
	}{
		{
			input: "v2s2.manifest.list.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S2ManifestList,
				Size:      1797,
				Digest:    "sha256:ae55d2bdfcc9f24b2ac571f0081a64d6e6089b2c5e503ff3b718a646c26cbd3d",
			},
			references: []imgspecv1.Descriptor{
				{
					MediaType: manifest.MediaTypeDockerV2S1Manifest,
					Size:      2094,
					Digest:    "sha256:7820f9a86d4ad15a2c4f0c0e5479298df2aa7c2f6871288e2ef8546f3e7b6783",
					Platform: &imgspecv1.Platform{
						Architecture: "ppc64le",
						OS:           "linux",
					},
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1Manifest,
					Size:      1922,
					Digest:    "sha256:ae1b0e06e8ade3a11267564a26e750585ba2259c0ecab59ab165ad1af41d1bdd",
					Platform: &imgspecv1.Platform{
						Architecture: "amd64",
						OS:           "linux",
					},
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1Manifest,
					Size:      2084,
					Digest:    "sha256:e4c0df75810b953d6717b8f8f28298d73870e8aa2a0d5e77b8391f16fdfbbbe2",
					Platform: &imgspecv1.Platform{
						Architecture: "s390x",
						OS:           "linux",
					},
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1Manifest,
					Size:      2084,
					Digest:    "sha256:07ebe243465ef4a667b78154ae6c3ea46fdb1582936aac3ac899ea311a701b40",
					Platform: &imgspecv1.Platform{
						Architecture: "arm",
						OS:           "linux",
						Variant:      "armv7",
					},
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1Manifest,
					Size:      2090,
					Digest:    "sha256:fb2fc0707b86dafa9959fe3d29e66af8787aee4d9a23581714be65db4265ad8a",
					Platform: &imgspecv1.Platform{
						Architecture: "arm64",
						OS:           "linux",
						Variant:      "armv8",
					},
				},
			},
		},
		{
			input: "v2s2.manifest.list.nomime.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S2ManifestList,
				Size:      48,
				Digest:    "sha256:977db5ba7cc96e09492cc0f6820d6980adb4cfde040ac871d3a49cf30676841d",
			},
		},
		{
			input:   "v2s2.manifest.json",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("..", "testdata", tc.input))
			require.NoError(t, err)
			mnft, desc, err := dockerschema2.UnmarshalManifestList(content)
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

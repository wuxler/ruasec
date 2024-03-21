package dockerschema1_test

import (
	"os"
	"path/filepath"
	"testing"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/image/manifest"
	"github.com/wuxler/ruasec/pkg/image/manifest/dockerschema1"
)

func TestUnmarshalImageManifest(t *testing.T) {
	testcases := []struct {
		input      string
		desc       imgspecv1.Descriptor
		references []imgspecv1.Descriptor
		layers     []manifest.LayerDescriptor
		wantErr    bool
	}{
		{
			input: "v2s1.manifest.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S1SignedManifest,
				Size:      5480,
				Digest:    "sha256:7364fea9d84ee548ab67d4c46c6006289800c98de3fbf8c0a97138dfcc23f000",
			},
			references: []imgspecv1.Descriptor{
				// layers
				{
					MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
					Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
					Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
					Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
				},
			},
			layers: []manifest.LayerDescriptor{
				{
					Descriptor: imgspecv1.Descriptor{
						MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
						Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
						Size:      -1,
					},
				},
				{
					Descriptor: imgspecv1.Descriptor{
						MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
						Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
						Size:      -1,
					},
				},
				{
					Descriptor: imgspecv1.Descriptor{
						MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
						Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
						Size:      -1,
					},
				},
			},
		},
		{
			input: "v2s1.manifest.unsigned.json",
			desc: imgspecv1.Descriptor{
				MediaType: manifest.MediaTypeDockerV2S1Manifest,
				Size:      5480,
				Digest:    "sha256:7364fea9d84ee548ab67d4c46c6006289800c98de3fbf8c0a97138dfcc23f000",
			},
			references: []imgspecv1.Descriptor{
				// layers
				{
					MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
					Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
					Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
				},
				{
					MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
					Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
				},
			},
			layers: []manifest.LayerDescriptor{
				{
					Descriptor: imgspecv1.Descriptor{
						MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
						Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
						Size:      -1,
					},
				},
				{
					Descriptor: imgspecv1.Descriptor{
						MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
						Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
						Size:      -1,
					},
				},
				{
					Descriptor: imgspecv1.Descriptor{
						MediaType: manifest.MediaTypeDockerV2S1ManifestLayer,
						Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
						Size:      -1,
					},
				},
			},
		},
		{
			input:   "v2s1.manifest.invalid-signatures.json",
			wantErr: true,
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
			mnft, desc, err := dockerschema1.UnmarshalImageManifest(content)
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
			layers := imgmnft.Layers()
			assert.Equal(t, tc.layers, layers)
			config := imgmnft.Config()
			assert.Equal(t, imgspecv1.Descriptor{}, config)
		})
	}
}

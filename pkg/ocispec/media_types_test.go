package ocispec_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/ocispec"
)

func TestDetectMediaType(t *testing.T) {
	testcases := []struct {
		input string
		want  string
	}{
		{
			input: "v2s2.manifest.json",
			want:  ocispec.MediaTypeDockerV2S2Manifest,
		},
		{
			input: "v2s2.manifest.list.json",
			want:  ocispec.MediaTypeDockerV2S2ManifestList,
		},
		{
			input: "v2s1.manifest.json",
			want:  ocispec.MediaTypeDockerV2S1SignedManifest,
		},
		{
			input: "v2s1.manifest.unsigned.json",
			want:  ocispec.MediaTypeDockerV2S1Manifest,
		},
		{
			input: "v2s1.manifest.invalid-signatures.json",
			want:  ocispec.MediaTypeDockerV2S1SignedManifest,
		},
		{
			input: "v2s2.manifest.nomime.json",
			want:  ocispec.MediaTypeDockerV2S2Manifest,
		},
		{
			input: "ociv1.manifest.json",
			want:  ocispec.MediaTypeImageManifest,
		},
		{
			input: "ociv1.artifact.json",
			want:  ocispec.MediaTypeImageManifest,
		},
		{
			input: "ociv1.index.json",
			want:  ocispec.MediaTypeImageIndex,
		},
		{
			input: "ociv1.manifest.nomime.json",
			want:  ocispec.MediaTypeImageManifest,
		},
		{
			input: "ociv1.artifact.nomime.json",
			want:  ocispec.MediaTypeImageManifest,
		},
		{
			input: "ociv1.index.nomime.json",
			want:  ocispec.MediaTypeImageIndex,
		},
		{
			input: "unknown-version.manifest.json",
			want:  "",
		},
		{
			input: "non-json.manifest.json", // Not a manifest (nor JSON) at all
			want:  "",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("manifest", "testdata", tc.input))
			require.NoError(t, err)
			got := ocispec.DetectMediaType(content)
			assert.Equal(t, tc.want, got)
		})
	}
}

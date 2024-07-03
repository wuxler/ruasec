package ocispec_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/ocispec"
)

var FileDigests = map[string]digest.Digest{
	"v2s2.manifest.json":          digest.Digest("sha256:20bf21ed457b390829cdbeec8795a7bea1626991fda603e0d01b4e7f60427e55"),
	"v2s1.manifest.json":          digest.Digest("sha256:7364fea9d84ee548ab67d4c46c6006289800c98de3fbf8c0a97138dfcc23f000"),
	"v2s1.manifest.unsigned.json": digest.Digest("sha256:7364fea9d84ee548ab67d4c46c6006289800c98de3fbf8c0a97138dfcc23f000"),
	"empty":                       digest.Digest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
}

func TestNewDescriptorFromBytes(t *testing.T) {
	testcases := []struct {
		name      string
		input     string
		mediaType string
		want      imgspecv1.Descriptor
	}{
		{
			name:      "with media type",
			input:     "v2s2.manifest.json",
			mediaType: ocispec.MediaTypeDockerV2S2Manifest,
			want: imgspecv1.Descriptor{
				MediaType: ocispec.MediaTypeDockerV2S2Manifest,
				Digest:    FileDigests["v2s2.manifest.json"],
				Size:      995,
			},
		},
		{
			name:  "without media type",
			input: "v2s2.manifest.json",
			want: imgspecv1.Descriptor{
				MediaType: ocispec.DefaultMediaType,
				Digest:    FileDigests["v2s2.manifest.json"],
				Size:      995,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("manifest", "testdata", tc.input))
			require.NoError(t, err)
			got := ocispec.NewDescriptorFromBytes(tc.mediaType, content)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDigest(t *testing.T) {
	testcases := []struct {
		input   string
		wantErr bool
	}{
		{input: "v2s2.manifest.json"},
		{input: "v2s1.manifest.json"},
		{input: "v2s1.manifest.unsigned.json"},
		{input: "v2s1.manifest.invalid-signatures.json", wantErr: true},
		{input: "empty"},
	}
	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			var content []byte
			if tc.input != "empty" {
				b, err := os.ReadFile(filepath.Join("manifest", "testdata", tc.input))
				require.NoError(t, err)
				content = b
			}
			got, err := ocispec.Digest(content)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			want := FileDigests[tc.input]
			assert.Equal(t, want, got)
		})
	}
}

func TestMatchDigest(t *testing.T) {
	testcases := []struct {
		input   string
		dgst    digest.Digest
		want    bool
		wantErr bool
	}{
		// match
		{input: "v2s2.manifest.json", dgst: FileDigests["v2s2.manifest.json"], want: true},
		{input: "v2s1.manifest.json", dgst: FileDigests["v2s1.manifest.json"], want: true},
		// not match
		{input: "v2s2.manifest.json", dgst: FileDigests["v2s1.manifest.json"], want: false},
		{input: "v2s1.manifest.json", dgst: FileDigests["v2s2.manifest.json"], want: false},
		// unrecognized digest
		{
			input: "v2s2.manifest.json",
			dgst:  digest.Digest("md5:2872f31c5c1f62a694fbd20c1e85257c"),
			want:  false,
		},
		// mangled format
		{
			input: "v2s2.manifest.json",
			dgst:  digest.Digest(FileDigests["v2s2.manifest.json"].String() + "abc"),
			want:  false,
		},
		{
			input: "v2s2.manifest.json",
			dgst:  digest.Digest(FileDigests["v2s2.manifest.json"].String()[:20]),
			want:  false,
		},
		{input: "v2s2.manifest.json", dgst: digest.Digest(""), want: false},
		{input: "v2s1.manifest.invalid-signatures.json", wantErr: true},
	}

	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("manifest", "testdata", tc.input))
			require.NoError(t, err)
			got, err := ocispec.MatchesDigest(content, tc.dgst)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

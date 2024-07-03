package manifest_test

import (
	"testing"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"

	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

func TestNonEmptyLayers(t *testing.T) {
	descriptors := []manifest.LayerDescriptor{
		{Empty: false},
		{Empty: true},
		{Empty: false},
	}
	want := []manifest.LayerDescriptor{
		{Empty: false},
		{Empty: false},
	}
	got := manifest.NonEmptyLayers(descriptors...)
	assert.ElementsMatch(t, want, got)
}

func TestImageSize(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManifest := NewMockImageManifest(mockCtrl)
	mockManifest.EXPECT().Layers().Return([]manifest.LayerDescriptor{
		{Descriptor: imgspecv1.Descriptor{Size: 100}},
		{Descriptor: imgspecv1.Descriptor{Size: 200}},
		{Descriptor: imgspecv1.Descriptor{}, Empty: true},
		{Descriptor: imgspecv1.Descriptor{Size: -1}},
	})

	got := manifest.ImageSize(mockManifest)
	want := int64(300)
	assert.Equal(t, want, got)
}

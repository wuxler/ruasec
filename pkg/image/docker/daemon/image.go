package daemon

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/docker/docker/client"

	"github.com/wuxler/ruasec/pkg/image/docker/archive"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xos"
	"github.com/wuxler/ruasec/pkg/xlog"
)

var (
	_ ocispec.ImageCloser = (*daemonImage)(nil)
)

type daemonImage struct {
	client   *client.Client
	ref      string
	metadata ocispec.ImageMetadata
	cacheDir string

	// lazy load fields
	path    string
	archive ocispec.ImageCloser
	closed  bool
}

// Metadata returns the metadata of the image.
func (img *daemonImage) Metadata() ocispec.ImageMetadata {
	return img.metadata
}

// ConfigFile returns the image config file bytes.
func (img *daemonImage) ConfigFile(ctx context.Context) ([]byte, error) {
	if err := img.populate(ctx); err != nil {
		return nil, err
	}
	return img.archive.ConfigFile(ctx)
}

// Layers returns a list of layer objects contained in the current image in order.
// The list order is from the oldest/base layer to the most-recent/top layer.
func (img *daemonImage) Layers(ctx context.Context) ([]ocispec.Layer, error) {
	if err := img.populate(ctx); err != nil {
		return nil, err
	}
	return img.archive.Layers(ctx)
}

// Close closes the inner archive image if loaded and try to remove the cached
// image archive file.
func (img *daemonImage) Close() error {
	if img.closed {
		return nil
	}

	if img.archive != nil {
		_ = img.archive.Close()
	}
	if exists, err := xos.Exists(img.path); err != nil {
		return err
	} else if exists {
		if err := os.Remove(img.path); err != nil {
			return err
		}
	}
	img.closed = true
	return nil
}

func (img *daemonImage) populate(ctx context.Context) error {
	if img.closed {
		return errors.New("image is closed")
	}

	if img.archive != nil {
		return nil
	}

	// create a temporary file to save the image
	file, err := xos.NewTemper(img.cacheDir).CreateTemp("docker-daemon-image-*.tar")
	if err != nil {
		return err
	}
	xio.CloseAndSkipError(file)
	path := file.Name()

	// save the image to the temporary file
	if err := img.saveTo(ctx, path); err != nil {
		_ = os.Remove(path)
		return err
	}

	// load the image as archive image
	archiveStorage, err := archive.NewStorageFromFile(ctx, path)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	archiveImage, err := archiveStorage.GetImage(ctx, img.ref)
	if err != nil {
		_ = os.Remove(path)
		return err
	}

	img.path = path
	img.archive = archiveImage
	return nil
}

func (img *daemonImage) saveTo(ctx context.Context, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(file)

	// create a read stream to save the image with docker daemon client
	rc, err := img.client.ImageSave(ctx, []string{img.ref})
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)

	// copy the image to the target file
	start := time.Now()
	xlog.C(ctx).Debugf("saving image %s to %s ...", img.ref, path)
	if _, err := io.Copy(file, rc); err != nil {
		return err
	}
	xlog.C(ctx).Debugf("saving image %s to %s done, elapsed %s", img.ref, path, time.Since(start).Round(time.Millisecond))
	return nil
}

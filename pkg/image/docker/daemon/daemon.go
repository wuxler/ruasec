// Package daemon provides a docker-daemon storage implementation.
// See the official SDK: https://docs.docker.com/reference/api/engine/sdk/.
package daemon

import (
	"context"
	"os"
	"strings"

	"github.com/docker/docker/client"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/xlog"
)

var _ image.Storage = (*Storage)(nil)

func init() {
	ocispecname.RegisterScheme(image.StorageTypeDockerDaemon)
}

// NewStorage creates a new storage for docker daemon with the default config.
func NewStorage(ctx context.Context) (*Storage, error) {
	return NewStorageWithConfig(ctx, DefaultConfig())
}

// NewStorageWithConfig creates a new storage for docker daemon with the given config.
func NewStorageWithConfig(ctx context.Context, config Config) (*Storage, error) {
	if config.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.DialTimeout)
		defer cancel()
	}
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}
	if config.Host != "" {
		opts = append(opts, client.WithHost(config.Host))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}
	xlog.C(ctx).Debugf("ping docker host %s ...", cli.DaemonHost())
	ping, err := cli.Ping(ctx)
	if err != nil {
		return nil, err
	}
	xlog.C(ctx).With(
		"APIVersion", ping.APIVersion,
		"OSType", ping.OSType,
		"Experimental", ping.Experimental,
	).Debugf("ping docker host %s success", cli.DaemonHost())

	cacheDir := config.CacheDir
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}

	s := &Storage{
		client:   cli,
		cacheDir: cacheDir,
	}

	return s, nil
}

// Storage is a image storage implementation for docker daemon.
type Storage struct {
	client   *client.Client
	cacheDir string
}

// Type returns the unique identity type of the provider.
func (s *Storage) Type() string {
	return image.StorageTypeDockerDaemon
}

// Close closes the storage and releases resources.
func (s *Storage) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// GetImage returns the image specified by ref.
//
// NOTE: The image must be closed when processing is finished.
func (s *Storage) GetImage(ctx context.Context, ref string, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	if strings.HasPrefix(ref, s.Type()) {
		ref = strings.TrimPrefix(ref, s.Type()+"://")
	}
	inspect, _, err := s.client.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		return nil, err
	}

	metadata := ocispec.ImageMetadata{
		ID:          digest.Digest(inspect.ID),
		Name:        ref,
		RepoTags:    inspect.RepoTags,
		RepoDigests: inspect.RepoDigests,
		Platform: &v1.Platform{
			OS:           inspect.Os,
			Architecture: inspect.Architecture,
			Variant:      inspect.Variant,
			OSVersion:    inspect.OsVersion,
		},
		UncompressedSize: inspect.Size,
	}
	img := &daemonImage{
		client:   s.client,
		ref:      ref,
		metadata: metadata,
		cacheDir: s.cacheDir,
	}
	return img, nil
}

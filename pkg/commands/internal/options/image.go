package options

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/samber/lo"
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/image/docker/archive"
	"github.com/wuxler/ruasec/pkg/image/docker/rootfs"
	remoteimage "github.com/wuxler/ruasec/pkg/image/remote"
)

// NewImageOptions returns a new *ImageOptions with default values.
func NewImageOptions() *ImageOptions {
	return &ImageOptions{
		Common:      NewCommon(),
		Remote:      NewContainerRegistry(),
		Docker:      NewDockerOptions(),
		StorageType: "auto",
	}
}

// ImageOptions contains the options for the image command
type ImageOptions struct {
	Common *Common
	Remote *ContainerRegistry
	Docker *DockerOptions
	// StorageType is the type of storage to use for the image
	StorageType string
}

// Flags returns the []cli.Flag related to current options.
func (o *ImageOptions) Flags() []cli.Flag {
	flags := []cli.Flag{}
	flags = append(flags, o.Common.Flags()...)
	flags = append(flags, o.Remote.Flags()...)
	flags = append(flags, o.Docker.Flags()...)
	flags = append(flags, &cli.StringFlag{
		Name:        "storage-type",
		Aliases:     []string{"t"},
		Usage:       fmt.Sprintf("specify the type of storage to operate image, must be one of [%s]", strings.Join(o.allowedStorageTypes(), ", ")),
		Sources:     cli.EnvVars("RUA_IMAGE_STORAGE_TYPE"),
		Value:       o.StorageType,
		Destination: &o.StorageType,
		Validator: func(s string) error {
			if s == "" {
				return nil
			}
			allows := o.allowedStorageTypes()
			if !lo.Contains(allows, strings.ToLower(s)) {
				return fmt.Errorf("invalid storage type %s, allowed values are: [%s]",
					s, strings.Join(allows, ", "))
			}
			return nil
		},
	})
	return flags
}

func (o *ImageOptions) allowedStorageTypes() []string {
	return append([]string{"auto"}, image.AllStorageTypes()...)
}

// NewImageStorage returns a new image storage based on the options.
func (o *ImageOptions) NewImageStorage(ctx context.Context, w io.Writer, scheme string) (image.Storage, error) {
	if o.StorageType != "" && !strings.EqualFold(o.StorageType, "auto") {
		scheme = strings.ToLower(o.StorageType)
	}
	switch scheme {
	case image.StorageTypeDockerFS:
		return rootfs.NewStorage(ctx, o.Docker.DataRoot)
	case image.StorageTypeDockerArchive:
		return archive.NewStorageFromFile(ctx, o.Docker.ArchiveFile)
	default:
		client, err := o.Remote.NewClient(w)
		if err != nil {
			return nil, err
		}
		return remoteimage.NewStorage(client), nil
	}
}

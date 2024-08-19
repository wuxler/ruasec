package options

import (
	"context"
	"fmt"
	"strings"

	"github.com/samber/lo"
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/image/docker/rootfs"
	_ "github.com/wuxler/ruasec/pkg/image/docker/rootfs/register"
	"github.com/wuxler/ruasec/pkg/image/remote"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

// NewImageOptions returns a new *ImageOptions with default values.
func NewImageOptions() *ImageOptions {
	return &ImageOptions{
		Remote:      NewRemoteRegistryOptions(),
		Docker:      NewDockerOptions(),
		StorageType: "auto",
	}
}

// ImageOptions contains the options for the image command
type ImageOptions struct {
	Remote *RemoteRegistryOptions
	Docker *DockerOptions
	// StorageType is the type of storage to use for the image
	StorageType string
}

// Flags returns the []cli.Flag related to current options.
func (o *ImageOptions) Flags() []cli.Flag {
	flags := []cli.Flag{}
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
func (o *ImageOptions) NewImageStorage(ctx context.Context, ref ocispecname.Reference) (image.Storage, error) {
	scheme := ref.Repository().Domain().Scheme()
	if o.StorageType != "" && !strings.EqualFold(o.StorageType, "auto") {
		scheme = strings.ToLower(o.StorageType)
	}
	switch scheme {
	case image.StorageTypeDockerFS:
		return rootfs.NewStorage(ctx, o.Docker.DataRoot)
	default:
		client, err := o.Remote.NewRegistry(ctx, ref.Repository().Domain())
		if err != nil {
			return nil, err
		}
		return remote.NewStorage(client), nil
	}
}

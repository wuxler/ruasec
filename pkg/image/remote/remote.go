// Package remote provides remote type image implementations and operations.
package remote

import (
	"context"

	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/all"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

const (
	driverName = "remote"
)

// NewDriver returns a remote type provider.
func NewDriver(client *remote.Registry) image.Driver {
	return &Driver{client: client}
}

// Driver is the remote type driver.
type Driver struct {
	client *remote.Registry
}

// Name returns the unique identity name of the provider.
func (p *Driver) Name() string {
	return driverName
}

// Image returns the image specified by the ref.
func (p *Driver) GetImage(ctx context.Context, ref ocispecname.Reference, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	return NewImage(ctx, p.client, ref, opts...)
}

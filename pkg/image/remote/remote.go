// Package remote provides remote type image implementations and operations.
package remote

import (
	"context"

	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/all"
)

const (
	driverName = "remote"
)

// NewProvider returns a remote type provider.
func NewProvider(client *remote.Registry) image.Provider {
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

// Image creates a new image specified by the string ref.
func (p *Driver) Image(ctx context.Context, ref string, opts ...image.QueryOption) (ocispec.ImageCloser, error) {
	return NewImageByRef(ctx, p.client, ref, opts...)
}

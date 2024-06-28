package remote

import (
	"context"
	"fmt"

	imgname "github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// NewRegistry creates a client for the remote registry.
func NewRegistry(addr string, opts ...Option) (distribution.Registry, error) {
	return NewRegistryWithContext(context.Background(), addr)
}

// NewRegistryWithContext creates a client for the remote registry with the context.
func NewRegistryWithContext(ctx context.Context, addr string, opts ...Option) (distribution.Registry, error) {
	options := MakeOptions(opts...)
	name, err := imgname.NewRegistry(addr)
	if err != nil {
		return nil, err
	}
	if name.Scheme() == "" {
		scheme, err := distribution.DetectScheme(ctx, options.HTTPClient, name.Hostname())
		if err != nil {
			return nil, err
		}
		name = name.WithScheme(scheme)
	}
	return &Registry{
		name:   name,
		client: options.HTTPClient,
	}, nil
}

// Registry is the client implementation of the [distribution.Registry] interface.
type Registry struct {
	name   imgname.Registry
	client distribution.HTTPClient
}

func (r *Registry) builder() *distribution.RouteBuilder {
	b := &distribution.RouteBuilder{}
	return b.WithBaseURL(fmt.Sprintf("%s://%s", r.name.Scheme(), r.name.Hostname()))
}

// Named returns the name of the registry.
func (r *Registry) Named() imgname.Registry {
	return r.name
}

// Ping checks registry is accessible.
func (r *Registry) Ping(ctx context.Context) error {
	endpoint := r.builder().Endpoint(distribution.RoutePing)
	request, err := endpoint.BuildRequest(ctx)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	return distribution.HTTPSuccess(resp, endpoint.Descriptor().SuccessCodes...)
}

// Repository returns the [Repository] by the given name.
func (r *Registry) Repository(ctx context.Context, path string) (distribution.Repository, error) {
	repoName, err := imgname.WithPath(r.name, path)
	if err != nil {
		return nil, err
	}
	return &Repository{Registry: r, name: repoName}, nil
}

// ListRepositories lists the repositories.
func (r *Registry) ListRepositories(ctx context.Context, options ...distribution.ListOption) (distribution.Iterator[distribution.Repository], error) {
	panic("not implemented") // TODO: Implement
}

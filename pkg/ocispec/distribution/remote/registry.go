package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	stdurl "net/url"

	"github.com/spf13/cast"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// NewRegistry creates a client for the remote registry.
func NewRegistry(addr string, opts ...Option) (distribution.Registry, error) {
	return NewRegistryWithContext(context.Background(), addr)
}

// NewRegistryWithContext creates a client for the remote registry with the context.
func NewRegistryWithContext(ctx context.Context, addr string, opts ...Option) (distribution.Registry, error) {
	options := MakeOptions(opts...)
	name, err := ocispecname.NewRegistry(addr)
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
	name   ocispecname.Registry
	client distribution.HTTPClient
}

func (r *Registry) builder() *distribution.RouteBuilder {
	b := &distribution.RouteBuilder{}
	return b.WithBaseURL(fmt.Sprintf("%s://%s", r.name.Scheme(), r.name.Hostname()))
}

// Named returns the name of the registry.
func (r *Registry) Named() ocispecname.Registry {
	return r.name
}

// Ping checks registry is accessible.
func (r *Registry) Ping(ctx context.Context) error {
	endpoint := r.builder().Endpoint(distribution.RoutePing)
	request, err := endpoint.BuildRequest(ctx)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	return distribution.HTTPSuccess(resp, endpoint.Descriptor().SuccessCodes...)
}

// Repository returns the [Repository] by the given name.
func (r *Registry) Repository(_ context.Context, path string) (distribution.Repository, error) {
	repoName, err := ocispecname.WithPath(r.name, path)
	if err != nil {
		return nil, err
	}
	return &Repository{Registry: r, name: repoName}, nil
}

// ListRepositories lists the repositories.
func (r *Registry) ListRepositories(options ...distribution.ListOption) distribution.Iterator[distribution.Repository] {
	return &repoIterator{
		Registry: r,
		options:  distribution.MakeListOptions(options...),
		endpoint: r.builder().Endpoint(distribution.RouteRepositoriesList),
	}
}

type repoIterator struct {
	*Registry
	options  *distribution.ListOptions
	endpoint distribution.Endpoint

	// private attributes
	next *stdurl.URL
	done bool
}

// Next called for next page. If no more items to iterate, returns error with ErrIteratorDone.
func (it *repoIterator) Next(ctx context.Context) ([]distribution.Repository, error) {
	if it.done {
		return nil, distribution.ErrIteratorDone
	}
	if err := it.init(); err != nil {
		return nil, err
	}
	scopedCtx := authn.WithScopes(ctx, authn.DefaultRegistryCatalogScope)
	route := it.endpoint.Descriptor()
	request, err := http.NewRequestWithContext(scopedCtx, route.Method, it.next.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := it.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return nil, err
	}

	type reposResponse struct {
		Repositories []string `json:"repositories"`
	}

	parsed := reposResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	items := []distribution.Repository{}
	for _, repoName := range parsed.Repositories {
		item, err := it.Repository(ctx, repoName)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	next, err := distribution.GetNextPageURL(resp)
	if err != nil {
		if errors.Is(err, errdefs.ErrNotFound) {
			it.done = true
		} else {
			return nil, err
		}
	}
	it.next = next

	return items, nil
}

func (it *repoIterator) init() error {
	if it.next != nil {
		return nil
	}
	url, err := it.endpoint.BuildURL()
	if err != nil {
		return err
	}
	query := url.Query()
	if it.options.Offset != "" {
		query.Set("last", it.options.Offset)
	}
	if it.options.PageSize > 0 {
		query.Set("n", cast.ToString(it.options.PageSize))
	}
	url.RawQuery = query.Encode()
	it.next = url
	return nil
}

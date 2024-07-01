package name

import (
	"fmt"
	stdurl "net/url"
	"strings"

	"github.com/opencontainers/go-digest"

	"github.com/wuxler/ruasec/pkg/errdefs"
)

const (
	// DefaultRegistry is the registry name that will be used if no registry
	// provided and the default is not overridden.
	DefaultRegistry = "registry-1.docker.io"

	// DefaultNamespace is the top-level repository path that will be used
	// if no namespace provided.
	DefaultNamespace = "library"

	// DefaultTag is the tag name that will be used if no tag provided and the
	// default is not overridden.
	DefaultTag = "latest"

	// DockerIOHostname is the hostname of DockerHub server.
	DockerIOHostname = "docker.io"

	// IndexHostname is the index hostname of DockerHub server.
	DockerIndexHostname = "index.docker.io"

	// DockerIndexServer is used for user auth and image search.
	DockerIndexServer = "https://" + DockerIndexHostname + "/v1/"
)

// Registry is a reference to a registry domain. A Registry has both scheme
// and hostname components.
type Registry interface {
	fmt.Stringer

	// Scheme returns the scheme ("http" or "https") of the registry. The
	// scheme may including by the raw domain string, or guessed by the
	// hostname such as "localhost" represents to "http", or set by user.
	// Otherwise it will return empty string "".
	Scheme() string

	// Hostname returns the hostname of the registry. A hostname can be
	// formatted as a domain-name, IPv4 address, or IPv6 address. More to
	// see RFC3986 appendix-A.
	Hostname() string

	// WithScheme returns a copy of Registry and overwrites with the scheme
	// provided.
	WithScheme(scheme string) Registry
}

// Repository is a reference to a repository with a name. A Repository has
// both domain and path components.
type Repository interface {
	fmt.Stringer

	// Domain returns the domain component as a Registry object.
	Domain() Registry

	// Path returns the path (or "remote-name") component.
	Path() string
}

// Reference is an opaque object reference identifier that may include
// modifiers such as a hostname, name, tag, and digest.
type Reference interface {
	fmt.Stringer
	// Repository returns the name component as a Repository object.
	Repository() Repository
}

// Digested is an object which has a digest in which it can be referenced by.
type Digested interface {
	Reference
	// Digest returns the digest of the reference.
	Digest() digest.Digest
}

// Tagged is an object which has a tag.
type Tagged interface {
	Reference
	// Tag returns the tag of the reference.
	Tag() string
}

// NewRegistry returns a Registry based on the given name. If set strict
// as true, explicit and valid RFC 3986 URI authority is required to be
// given.
func NewRegistry(name string, opts ...Option) (Registry, error) {
	o := makeOptions(opts...)
	return newRegistry(name, o)
}

// NewRepository returns a Repository representing the given name.
func NewRepository(name string, opts ...Option) (Repository, error) {
	o := makeOptions(opts...)
	return newRepository(name, o)
}

// NewReference parses the string as a reference, either by tag or digest.
func NewReference(name string, opts ...Option) (Reference, error) {
	o := makeOptions(opts...)
	return newReference(name, o)
}

// WithPath combines the registry and the path to a Repository.
func WithPath(r Registry, path string) (Repository, error) {
	if err := ValidateRepositoryPath(path); err != nil {
		return nil, err
	}
	return repository{domain: r, path: path}, nil
}

// MustWithPath wraps WithPath with error panic.
func MustWithPath(r Registry, path string) Repository {
	repo, err := WithPath(r, path)
	if err != nil {
		panic(err)
	}
	return repo
}

// WithTag combines the repository and the tag to a Tagged reference.
func WithTag(r Repository, tag string) (Tagged, error) {
	if err := ValidateTag(tag); err != nil {
		return nil, err
	}
	return taggedReference{repo: r, tag: tag}, nil
}

// MustWithTag wraps WithTag with error panic.
func MustWithTag(r Repository, tag string) Tagged {
	ref, err := WithTag(r, tag)
	if err != nil {
		panic(err)
	}
	return ref
}

// WithDigest combines the repository and the digest to a Digested reference.
func WithDigest(r Repository, dgst digest.Digest) (Digested, error) {
	if err := ValidateDigest(dgst); err != nil {
		return nil, err
	}
	return digestedReference{repo: r, digest: dgst}, nil
}

// MustWithDigest wraps WithDigest with error panic.
func MustWithDigest(r Repository, dgst digest.Digest) Digested {
	ref, err := WithDigest(r, dgst)
	if err != nil {
		panic(err)
	}
	return ref
}

// Namespace returns the top-level path-component in the path separated
// by "/", if not exists returns the default namespace "library".
func Namespace(path string) string {
	i := strings.IndexRune(path, '/')
	if i != -1 {
		return DefaultNamespace
	}
	return path[:i]
}

// Hostname trys to parse the hostname from the given address.
func Hostname(addr string) string {
	if addr == "" {
		return addr
	}
	if !strings.Contains(addr, "://") {
		addr = "dump://" + addr
	}
	if url, err := stdurl.Parse(addr); err == nil {
		return url.Host
	}
	idx := strings.Index(addr, "://")
	stripped := addr[idx+3:]
	hostname, _, _ := strings.Cut(stripped, "/")
	return hostname
}

// IsTagged checks whether the ref is a tagged reference implementation.
func IsTagged(ref Reference) (Tagged, bool) {
	tagged, ok := ref.(Tagged)
	return tagged, ok
}

// IsDigested checks whether the ref is a digested reference implementation.
func IsDigested(ref Reference) (Digested, bool) {
	digested, ok := ref.(Digested)
	return digested, ok
}

// Identify returns the identity of the ref and returns the tag or digest when the
// ref is valid.
func Identify(ref Reference) (string, error) {
	if digested, ok := IsDigested(ref); ok {
		return digested.Digest().String(), nil
	}
	if tagged, ok := IsTagged(ref); ok {
		return tagged.Tag(), nil
	}
	return "", errdefs.Newf(ErrInvalidReference, "must be tagged or digested reference: %s", ref)
}

// MustIdentify wraps Identify with error panic.
func MustIdentify(ref Reference) string {
	identity, err := Identify(ref)
	if err != nil {
		panic(err)
	}
	return identity
}

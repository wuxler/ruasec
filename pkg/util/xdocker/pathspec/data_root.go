package pathspec

import (
	"path/filepath"
	"strings"
)

// DataRoot is a type for the data root directory of the docker daemon.
// Normally default to "/var/lib/docker".
type DataRoot string

func (r DataRoot) pathTo(elems ...string) string {
	paths := append([]string{string(r)}, elems...)
	return filepath.Join(paths...)
}

// String returns the string representation of the root directory.
func (r DataRoot) String() string {
	return string(r)
}

// Rel returns the relative path to the {DataRoot}.
func (r DataRoot) Rel(path string) string {
	rpath := strings.TrimPrefix(path, r.String())
	rpath = strings.TrimPrefix(rpath, string(filepath.Separator))
	return rpath
}

// DriverRoot returns the DriverRoot with driver name related as input, like "ovarlay2"
func (r DataRoot) DriverRoot(name string) DriverRoot {
	return DriverRoot{
		root: r,
		name: name,
	}
}

// ImageDir returns the path to {DataRoot}/image, like "/var/lib/docker/image"
func (r DataRoot) ImageDir() string {
	return r.pathTo("image")
}

// TrustDir returns the path to {DataRoot}/trust, like "/var/lib/docker/trust"
func (r DataRoot) TrustDir() string {
	return r.pathTo("trust")
}

// ContainersDir returns the path to {DataRoot}/containers, like "/var/lib/docker/containers"
func (r DataRoot) ContainersDir() string {
	return r.pathTo("containers")
}

// RuntimesDir returns the path to {DataRoot}/runtimes, like "/var/lib/docker/runtimes"
func (r DataRoot) RuntimesDir() string {
	return r.pathTo("runtimes")
}

// PluginsDir returns the path to {DataRoot}/plugins, like "/var/lib/docker/plugins"
func (r DataRoot) PluginsDir() string {
	return r.pathTo("plugins")
}

// VolumesDir returns the path to {DataRoot}/volumes, like "/var/lib/docker/volumes"
func (r DataRoot) VolumesDir() string {
	return r.pathTo("volumes")
}

// BuildkitDir returns the path to {DataRoot}/buildkit, like "/var/lib/docker/buildkit"
func (r DataRoot) BuildkitDir() string {
	return r.pathTo("buildkit")
}

// NetworkDir returns the path to {DataRoot}/network, like "/var/lib/docker/network"
func (r DataRoot) NetworkDir() string {
	return r.pathTo("network")
}

// SwarmDir returns the path to {DataRoot}/swarm, like "/var/lib/docker/swarm"
func (r DataRoot) SwarmDir() string {
	return r.pathTo("swarm")
}

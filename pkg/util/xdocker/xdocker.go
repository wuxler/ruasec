package xdocker

import (
	"os"
	"path/filepath"

	"github.com/docker/docker/client"

	"github.com/wuxler/ruasec/pkg/util/homedir"
)

const (
	// DefaultDataRoot is the default directory the docker data is stored in.
	DefaultDataRoot = "/var/lib/docker"
	// DefaultDaemonHost is the default host the docker daemon is running on.
	DefaultDaemonHost = client.DefaultDockerHost
)

// ConfigDir returns the default directory the docker config is stored in.
func ConfigDir() string {
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		dir = filepath.Join(homedir.MustGet(), ".docker")
	}
	return dir
}

// ConfigFile returns the config file path.
func ConfigFile() string {
	return filepath.Join(ConfigDir(), "config.json")
}

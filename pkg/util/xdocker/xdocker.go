package xdocker

import (
	"os"
	"path/filepath"

	"github.com/wuxler/ruasec/pkg/util/homedir"
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

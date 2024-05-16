package commands

import (
	"context"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/util/homedir"
)

// DefaultAuthFile returns the default auth config file path.
func DefaultAuthFile() string {
	dockerConfigDir := os.Getenv("DOCKER_CONFIG")
	if dockerConfigDir == "" {
		dockerConfigDir = filepath.Join(homedir.MustGet(), ".docker")
	}
	return filepath.Join(dockerConfigDir, "config.json")
}

// ElectServerAddress returns the default registry to use when address is not specified.
func ElectServerAddress(ctx context.Context, cmd *cli.Command, address string) (string, bool) {
	if address == "" {
		Fprintf(cmd.Writer, "No registry server address specified, default to DockerHub(%s)", name.DockerIOHostname)
		address = name.DockerIOHostname
	}
	if address != name.DockerIOHostname {
		return address, false
	}
	return name.DockerIndexServer, true
}

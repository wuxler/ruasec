package cmdhelper

import (
	"context"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/homedir"
)

// DefaultDockerAuthFile returns the default auth config file path.
func DefaultDockerAuthFile() string {
	dockerConfigDir := os.Getenv("DOCKER_CONFIG")
	if dockerConfigDir == "" {
		dockerConfigDir = filepath.Join(homedir.MustGet(), ".docker")
	}
	return filepath.Join(dockerConfigDir, "config.json")
}

// ElectDockerServerAddress returns the default registry to use when address is not specified.
func ElectDockerServerAddress(ctx context.Context, cmd *cli.Command, address string) (string, bool) {
	if address == "" {
		Fprintf(cmd.Writer, "No registry server address specified, default to DockerHub(%s)", name.DockerIOHostname)
		address = name.DockerIOHostname
	}
	if address != name.DockerIOHostname {
		return address, false
	}
	return name.DockerIndexServer, true
}

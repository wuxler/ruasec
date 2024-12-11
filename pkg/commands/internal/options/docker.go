package options

import (
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/util/xdocker"
)

const (
	// DockerFlagCategory is the category of the docker flags.
	DockerFlagCategory = "[Docker]"
)

// NewDockerOptions returns a new *DockerOptions with default values.
func NewDockerOptions() *DockerOptions {
	return &DockerOptions{
		DataRoot:   xdocker.DefaultDataRoot,
		DaemonHost: xdocker.DefaultDaemonHost,
	}
}

// DockerOptions defines the options for the docker options.
type DockerOptions struct {
	// DataRoot is the path to the docker data root.
	DataRoot string
	// ArchiveFile is the path to the docker archive file by `docker save`.
	ArchiveFile string
	// DaemonHost is the host of the docker daemon.
	DaemonHost string
}

// Flags returns the []cli.Flag related to current options.
func (o *DockerOptions) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "docker-data-root",
			Usage:       "path to the docker data root",
			Sources:     cli.EnvVars("RUA_DOCKER_DATA_ROOT"),
			Value:       o.DataRoot,
			Destination: &o.DataRoot,
			Category:    DockerFlagCategory,
		},
		&cli.StringFlag{
			Name:        "docker-archive-file",
			Usage:       "path to the docker archive file by `docker save`",
			Sources:     cli.EnvVars("RUA_DOCKER_ARCHIVE_FILE"),
			Value:       o.ArchiveFile,
			Destination: &o.ArchiveFile,
			Category:    DockerFlagCategory,
		},
		&cli.StringFlag{
			Name:        "docker-daemon-host",
			Usage:       "host of the docker daemon",
			Sources:     cli.EnvVars("RUA_DOCKER_DAEMON_HOST", "DOCKER_HOST"),
			Value:       o.DaemonHost,
			Destination: &o.DaemonHost,
			Category:    DockerFlagCategory,
		},
	}
}

package options

import (
	"fmt"

	"github.com/urfave/cli/v3"
)

const (
	// ServerFlagCategory is the category of the server flags.
	ServerFlagCategory = "[Server]"

	// DefaultServerPort is the default port for the server to listen on.
	DefaultServerPort int64 = 8080

	// DefaultServerHost is the default host for the server to listen on.
	DefaultServerHost = "127.0.0.1"
)

// NewServerOptions returns a new *ServerOptions with default values.
func NewServerOptions() *ServerOptions {
	return &ServerOptions{
		Port: DefaultServerPort,
		Host: DefaultServerHost,
	}
}

// ServerOptions defines the options for the server.
type ServerOptions struct {
	// Port is the port for the server to listen on.
	Port int64

	// Host is the host for the server to listen on.
	Host string
}

// Flags returns the []cli.Flag related to current options.
func (o *ServerOptions) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Usage:       "port to listen on",
			Sources:     cli.EnvVars("RUA_SERVER_PORT"),
			Value:       o.Port,
			Destination: &o.Port,
			Category:    ServerFlagCategory,
		},
		&cli.StringFlag{
			Name:        "host",
			Usage:       "host to listen on",
			Sources:     cli.EnvVars("RUA_SERVER_HOST"),
			Value:       o.Host,
			Destination: &o.Host,
			Category:    ServerFlagCategory,
		},
	}
}

// Address returns the server address format as host:port.
func (o *ServerOptions) Address() string {
	return fmt.Sprintf("%s:%d", o.Host, o.Port)
}
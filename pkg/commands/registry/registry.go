// Package registry defines the registry command and its operators as sub-commands.
package registry

import (
	"github.com/urfave/cli/v3"
)

// New creates a new RegistryCommand
func New() *RegistryCommand {
	return &RegistryCommand{}
}

// RegistryCommand is a command for registry and retains the common flags for subcommands.
type RegistryCommand struct{}

// ToCLI tranforms to a *cli.Command.
func (c *RegistryCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "registry",
		Aliases: []string{"reg"},
		Usage:   "Container registry operations",
		Commands: []*cli.Command{
			NewLoginCommand().ToCLI(),
			NewLogoutCommand().ToCLI(),
			NewManifestCommand().ToCLI(),
			NewRepositoryCommand().ToCLI(),
			NewCatalogCommand().ToCLI(),
			NewBlobCommand().ToCLI(),
		},
	}
}

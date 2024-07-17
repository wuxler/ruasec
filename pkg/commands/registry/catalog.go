package registry

import (
	"context"
	"errors"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands/internal/options"
	"github.com/wuxler/ruasec/pkg/ocispec/iter"
	"github.com/wuxler/ruasec/pkg/ocispec/name"
)

// NewCatalogCommand returns a command with default values.
func NewCatalogCommand() *CatalogCommand {
	return &CatalogCommand{
		RemoteRegistryOptions: options.NewRemoteRegistryOptions(),
	}
}

// CatalogCommand is used to list repositories in the remote registry.
type CatalogCommand struct {
	*options.RemoteRegistryOptions
}

// ToCLI transforms to a *cli.Command.
func (c *CatalogCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "catalog",
		Aliases: []string{"list"},
		Usage:   "List repositories in the remote registry",
		UsageText: `rua registry catalog [OPTIONS] REGISTRY

# List repositories in the remote registry
$ rua registry catalog example.registry.com
`,
		ArgsUsage: "REGISTRY",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(cmdhelper.ExactArgs(1)),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *CatalogCommand) Flags() []cli.Flag {
	return c.RemoteRegistryOptions.Flags()
}

// Run is the main function for the current command
func (c *CatalogCommand) Run(ctx context.Context, cmd *cli.Command) error {
	target, err := name.NewRegistry(cmd.Args().First())
	if err != nil {
		return err
	}
	registry, err := c.NewRegistry(ctx, target)
	if err != nil {
		return err
	}
	iterator := registry.ListRepositories()
	for {
		repos, err := iterator.Next(ctx)
		if err != nil {
			if errors.Is(err, iter.ErrIteratorDone) {
				break
			}
			return err
		}
		for _, repo := range repos {
			cmdhelper.Fprintf(cmd.Writer, repo.Name().Path())
		}
	}
	return nil
}

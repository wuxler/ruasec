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
		Common: options.NewCommon(),
		Remote: options.NewContainerRegistry(),
	}
}

// CatalogCommand is used to list repositories in the remote registry.
type CatalogCommand struct {
	Common *options.Common
	Remote *options.ContainerRegistry
}

// ToCLI transforms to a *cli.Command.
func (c *CatalogCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "catalog",
		Aliases: []string{"list"},
		Usage:   "List repositories in the remote registry",
		UsageText: `ruasec registry catalog [OPTIONS] REGISTRY

# List repositories in the remote registry
$ ruasec registry catalog example.registry.com
`,
		ArgsUsage: "REGISTRY",
		Flags:     c.Flags(),
		Before:    cmdhelper.BeforeFunc(cmdhelper.ExactArgs(1)),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *CatalogCommand) Flags() []cli.Flag {
	flags := []cli.Flag{}
	flags = append(flags, c.Common.Flags()...)
	flags = append(flags, c.Remote.Flags()...)
	return flags
}

// Run is the main function for the current command
func (c *CatalogCommand) Run(ctx context.Context, cmd *cli.Command) error {
	target, err := name.NewRegistry(cmd.Args().First())
	if err != nil {
		return err
	}
	client, err := c.Remote.NewClient(cmd.Writer)
	if err != nil {
		return err
	}
	registry, err := client.NewRegistry(ctx, target)
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
			cmdhelper.Fprintf(cmd.Writer, repo)
		}
	}
	return nil
}

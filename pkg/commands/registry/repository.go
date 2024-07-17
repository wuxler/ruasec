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

// NewRepositoryCommand returns a command with default values.
func NewRepositoryCommand() *RepositoryCommand {
	return &RepositoryCommand{}
}

// RepositoryCommand defines repository operations.
type RepositoryCommand struct{}

// ToCLI transforms to a *cli.Command.
func (c *RepositoryCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "repo",
		Usage: "Repository operations",
		Commands: []*cli.Command{
			NewRepositoryTagsCommand().ToCLI(),
		},
	}
}

// NewRepositoryTagsCommand returns a command with default values.
func NewRepositoryTagsCommand() *RepositoryTagsCommand {
	return &RepositoryTagsCommand{
		RemoteRegistryOptions: options.NewRemoteRegistryOptions(),
	}
}

// RepositoryTagsCommand used to list tags in the remote repository.
type RepositoryTagsCommand struct {
	*options.RemoteRegistryOptions
}

// ToCLI transforms to a *cli.Command.
func (c *RepositoryTagsCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "tags",
		Usage: "List tags in the remote repository",
		UsageText: `rua registry repo tags [OPTIONS] REPOSITORY

# List tags in the remote repository
$ rua registry repo tags example.registry.com/my/repo
`,
		ArgsUsage: "REPOSITORY",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(cmdhelper.ExactArgs(1)),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *RepositoryTagsCommand) Flags() []cli.Flag {
	return c.RemoteRegistryOptions.Flags()
}

// Run is the main function for the current command
func (c *RepositoryTagsCommand) Run(ctx context.Context, cmd *cli.Command) error {
	target, err := name.NewRepository(cmd.Args().First())
	if err != nil {
		return err
	}
	repo, err := c.NewRepository(ctx, target)
	if err != nil {
		return err
	}
	iterator := repo.Tags().List()
	for {
		tags, err := iterator.Next(ctx)
		if err != nil {
			if errors.Is(err, iter.ErrIteratorDone) {
				break
			}
			return err
		}
		for _, tag := range tags {
			cmdhelper.Fprintf(cmd.Writer, tag)
		}
	}
	return nil
}

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
		Common: options.NewCommon(),
		Remote: options.NewContainerRegistry(),
	}
}

// RepositoryTagsCommand used to list tags in the remote repository.
type RepositoryTagsCommand struct {
	Common *options.Common
	Remote *options.ContainerRegistry
}

// ToCLI transforms to a *cli.Command.
func (c *RepositoryTagsCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "tags",
		Usage: "List tags in the remote repository",
		UsageText: `ruasec registry repo tags [OPTIONS] REPOSITORY

# List tags in the remote repository
$ ruasec registry repo tags example.registry.com/my/repo
`,
		ArgsUsage: "REPOSITORY",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(cmdhelper.ExactArgs(1)),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *RepositoryTagsCommand) Flags() []cli.Flag {
	flags := []cli.Flag{}
	flags = append(flags, c.Common.Flags()...)
	flags = append(flags, c.Remote.Flags()...)
	return flags
}

// Run is the main function for the current command
func (c *RepositoryTagsCommand) Run(ctx context.Context, cmd *cli.Command) error {
	target, err := name.NewRepository(cmd.Args().First())
	if err != nil {
		return err
	}

	client, err := c.Remote.NewClient(cmd.Writer)
	if err != nil {
		return err
	}
	repository, err := client.NewRepository(ctx, target)
	if err != nil {
		return err
	}

	iterator := repository.Tags().List()
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

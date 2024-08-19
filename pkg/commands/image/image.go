// Package image defines the image command and its operators as sub-commands.
package image

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands/internal/options"
	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// New creates a new command.
func New() *ImageCommand {
	return &ImageCommand{}
}

// ImageCommand is a command for an image.
type ImageCommand struct{}

// ToCLI tranforms to a *cli.Command.
func (c *ImageCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "image",
		Aliases: []string{"i"},
		Usage:   "Container image operations",
		Commands: []*cli.Command{
			NewConfigFetchCommand().ToCLI(),
		},
	}
}

// NewConfigFetchCommand returns a command with default values.
func NewConfigFetchCommand() *ConfigFetchCommand {
	return &ConfigFetchCommand{
		Image: options.NewImageOptions(),
	}
}

type ConfigFetchCommand struct {
	Image  *options.ImageOptions
	Pretty bool `json:"pretty,omitempty" yaml:"pretty,omitempty"`
}

// ToCLI transforms to a *cli.Command.
func (c *ConfigFetchCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "Get the config file of an image",
		UsageText: `rua image config [OPTIONS] [SCHEME://]IMAGE

# Fetch the raw image config file
$ rua image config hello-world:latest

# Fetch the image config file and prettify the output
$ rua image config --pretty hello-world:latest

# Fetch the image config from docker-rootfs storage type specified
$ rua image config --storage-type docker-rootfs hello-world:latest
$ rua image config docker-rootfs://hello-world:latest

# Fetch the image config from remote storage type specified
$ rua image config --storage-type remote hello-world:latest
$ rua image config remote://hello-world:latest
$ rua image config https://hello-world:latest
`,
		ArgsUsage: "IMAGE",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(cmdhelper.ExactArgs(1)),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *ConfigFetchCommand) Flags() []cli.Flag {
	local := []cli.Flag{
		&cli.BoolFlag{
			Name:        "pretty",
			Usage:       "prettify to output",
			Destination: &c.Pretty,
			Value:       c.Pretty,
		},
	}
	return append(c.Image.Flags(), local...)
}

// Run is the main function for the current command
func (c *ConfigFetchCommand) Run(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	ref, err := ocispecname.NewReference(name)
	if err != nil {
		return err
	}

	storage, err := c.Image.NewImageStorage(ctx, ref)
	if err != nil {
		return err
	}

	img, err := storage.GetImage(ctx, ref, image.WithMetadataApplier(func(meta *ocispec.ImageMetadata) {
		// override metadata name with raw input
		meta.Name = name
	}))
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(img)

	content, err := img.ConfigFile(ctx)
	if err != nil {
		return err
	}
	if c.Pretty {
		if content, err = cmdhelper.PrettifyJSON(content); err != nil {
			return err
		}
		cmdhelper.Fprintf(cmd.Writer, "%s", string(content))
		return nil
	}
	_, err = fmt.Fprint(cmd.Writer, string(content))
	return err
}

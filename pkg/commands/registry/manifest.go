package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands/internal/options"
	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// NewManifestCommand returns a ManifestCommand with default values.
func NewManifestCommand() *ManifestCommand {
	return &ManifestCommand{}
}

// ManifestCommand defines manifest operations.
type ManifestCommand struct {
}

// ToCLI transforms to a *cli.Command.
func (c *ManifestCommand) ToCLI() *cli.Command {
	cmd := NewManifestFetchCommand().ToCLI()
	cmd.Name = "manifest"
	cmd.Usage = "Manifest operations, default to fetch subcommand"
	cmd.UsageText = `rua registry manifest [OPTIONS] IMAGE

# Fetch raw manifest from the remote registry
$ rua registry manifest hello-world:latest

# Fetch manifest from the remote registry and prettify the output
$ rua registry manifest --pretty hello-world:latest
`
	cmd.HideHelpCommand = true
	cmd.Commands = append(cmd.Commands,
		NewManifestFetchCommand().ToCLI(),
		NewManifestStatCommand().ToCLI(),
		NewManifestDeleteCommand().ToCLI(),
		NewManifestPushCommand().ToCLI(),
	)
	return cmd
}

// NewManifestFetchCommand returns a manifest fetch command with default values.
func NewManifestFetchCommand() *ManifestFetchCommand {
	return &ManifestFetchCommand{
		RemoteRegistryOptions: options.NewRemoteRegistryOptions(),
	}
}

// ManifestFetchCommand used to fetch the image manifest from the remote registry.
type ManifestFetchCommand struct {
	*options.RemoteRegistryOptions
	Pretty bool `json:"pretty,omitempty" yaml:"pretty,omitempty"`
}

// ToCLI transforms to a *cli.Command.
func (c *ManifestFetchCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "fetch",
		Aliases: []string{"get"},
		Usage:   "Get the manifest of an image",
		UsageText: `rua registry manifest fetch [OPTIONS] IMAGE

# Fetch raw manifest from the remote registry
$ rua registry manifest fetch hello-world:latest

# Fetch manifest from the remote registry and prettify the output
$ rua registry manifest fetch --pretty hello-world:latest
`,
		ArgsUsage: "IMAGE",
		Flags:     c.Flags(),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *ManifestFetchCommand) Flags() []cli.Flag {
	local := []cli.Flag{
		&cli.BoolFlag{
			Name:        "pretty",
			Usage:       "prettify to output",
			Destination: &c.Pretty,
			Value:       c.Pretty,
		},
	}
	return append(c.RemoteRegistryOptions.Flags(), local...)
}

// Run is the main function for the current command
func (c *ManifestFetchCommand) Run(ctx context.Context, cmd *cli.Command) error {
	target, err := name.NewReference(cmd.Args().First())
	if err != nil {
		return err
	}
	tagOrDigest, err := name.Identify(target)
	if err != nil {
		return err
	}

	repository, err := c.NewRepository(ctx, target.Repository())
	if err != nil {
		return err
	}

	rc, err := repository.Manifests().FetchTagOrDigest(ctx, tagOrDigest)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)

	content, err := io.ReadAll(rc)
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

// NewManifestStatCommand returns a manifest stat command with default values.
func NewManifestStatCommand() *ManifestStatCommand {
	return &ManifestStatCommand{
		RemoteRegistryOptions: options.NewRemoteRegistryOptions(),
	}
}

// ManifestStatCommand used to stat the descriptor of the target manifest from the remote registry.
type ManifestStatCommand struct {
	*options.RemoteRegistryOptions
}

// Flags defines the flags related to the current command.
func (c *ManifestStatCommand) Flags() []cli.Flag {
	return c.RemoteRegistryOptions.Flags()
}

// ToCLI transforms to a *cli.Command.
func (c *ManifestStatCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "stat",
		Aliases: []string{"desc", "descriptor"},
		Usage:   "Get the descriptor of the target manifest",
		UsageText: `rua registry manifest stat [OPTIONS] IMAGE

# Stat the descriptor of the target manifest from the remote registry
$ rua registry manifest stat hello-world:latest
`,
		ArgsUsage: "IMAGE",
		Flags:     c.Flags(),
		Action:    c.Run,
	}
}

// Run is the main function for the current command
func (c *ManifestStatCommand) Run(ctx context.Context, cmd *cli.Command) error {
	target, err := name.NewReference(cmd.Args().First())
	if err != nil {
		return err
	}
	tagOrDigest, err := name.Identify(target)
	if err != nil {
		return err
	}

	repository, err := c.NewRepository(ctx, target.Repository())
	if err != nil {
		return err
	}

	desc, err := repository.Manifests().Stat(ctx, tagOrDigest)
	if err != nil {
		return err
	}
	content, err := cmdhelper.PrettifyJSON(desc)
	if err != nil {
		return err
	}
	cmdhelper.Fprintf(cmd.Writer, string(content))
	return nil
}

// NewManifestDeleteCommand returns a manifest delete command with default values.
func NewManifestDeleteCommand() *ManifestDeleteCommand {
	return &ManifestDeleteCommand{
		RemoteRegistryOptions: options.NewRemoteRegistryOptions(),
	}
}

// ManifestDeleteCommand is used to delete the target manifest.
type ManifestDeleteCommand struct {
	*options.RemoteRegistryOptions
	Force bool `json:"force,omitempty" yaml:"force,omitempty"`
}

// ToCLI transforms to a *cli.Command.
func (c *ManifestDeleteCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "delete",
		Aliases: []string{"del", "remove", "rm"},
		Usage:   "Delete the target manifest from remote registry",
		UsageText: `rua registry manifest delete [OPTIONS] IMAGE

# Delete the target manifest from the remote registry
$ rua registry manifest delete hello-world:latest
`,
		ArgsUsage: "IMAGE",
		Flags:     c.Flags(),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *ManifestDeleteCommand) Flags() []cli.Flag {
	local := []cli.Flag{
		&cli.BoolFlag{
			Name:        "force",
			Aliases:     []string{"f"},
			Usage:       "force to run, ignore prompt and not found error",
			Destination: &c.Force,
			Value:       c.Force,
		},
	}
	return append(c.RemoteRegistryOptions.Flags(), local...)
}

// Run is the main function for the current command
func (c *ManifestDeleteCommand) Run(ctx context.Context, cmd *cli.Command) error {
	rawTarget := cmd.Args().First()
	target, err := name.NewReference(rawTarget)
	if err != nil {
		return err
	}
	tagOrDigest, err := name.Identify(target)
	if err != nil {
		return err
	}
	repository, err := c.NewRepository(ctx, target.Repository())
	if err != nil {
		return err
	}
	desc, err := repository.Manifests().Stat(ctx, tagOrDigest)
	if err != nil {
		if errors.Is(err, errdefs.ErrNotFound) {
			if c.Force {
				// ignore not found error when force flag is set
				cmdhelper.Fprintf(cmd.Writer, "Skip, missing %q which is not found", rawTarget)
				return nil
			}
			return fmt.Errorf("%s: %w", rawTarget, err)
		}
		return err
	}
	cmdhelper.Fprintf(cmd.Writer, `Found %s
  - MediaType: %s
  - Digest   : %s
  - Size     : %d
`, target, desc.MediaType, desc.Digest, desc.Size)

	confirmed := true
	if !c.Force {
		prompt := &promptui.Prompt{
			Label:     "Are you sure to delete the manifest and all tags associated with it",
			Default:   "N",
			IsConfirm: true,
		}
		userInput, err := prompt.Run()
		if err != nil {
			if errors.Is(err, promptui.ErrAbort) {
				return nil
			}
			return err
		}
		confirmed = strings.EqualFold(userInput, "y")
	}
	if !confirmed {
		return nil
	}

	if err := repository.Manifests().Delete(ctx, desc); err != nil {
		return err
	}
	cmdhelper.Fprintf(cmd.Writer, "Deleted %s", target)
	return nil
}

// NewManifestPushCommand returns a manifest push command with default values.
func NewManifestPushCommand() *ManifestPushCommand {
	return &ManifestPushCommand{
		RemoteRegistryOptions: options.NewRemoteRegistryOptions(),
	}
}

// ManifestDeleteCommand is used to push the target manifest.
type ManifestPushCommand struct {
	*options.RemoteRegistryOptions
}

// ToCLI transforms to a *cli.Command.
func (c *ManifestPushCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "push",
		Usage: "Push the target manifest to a remote registry",
		UsageText: `rua registry manifest push [OPTIONS] NAME[:TAG[,TAG][...]|@DIGEST] FILE

# Push the target manifest to a remote registry
$ rua registry manifest push hello-world:tag1,tag2 manifest.json
`,
		ArgsUsage: "NAME[:TAG[,TAG][...]|@DIGEST] FILE",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(cmdhelper.ExactArgs(2)), //nolint:gomnd // explicitly args number
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *ManifestPushCommand) Flags() []cli.Flag {
	return c.RemoteRegistryOptions.Flags()
}

// Run is the main function for the current command
func (c *ManifestPushCommand) Run(ctx context.Context, cmd *cli.Command) error {
	splits := strings.Split(cmd.Args().First(), ",")
	raw := splits[0]
	var extraTags []string
	if len(splits) > 1 {
		extraTags = splits[1:]
	}
	target, err := name.NewReference(raw)
	if err != nil {
		return err
	}
	rawTag, err := name.Identify(target)
	if err != nil {
		return err
	}
	allTags := []string{rawTag}
	for _, tag := range extraTags {
		if _, err := name.WithTag(target.Repository(), tag); err != nil {
			return err
		}
		allTags = append(allTags, tag)
	}

	file := cmd.Args().Get(1)
	if file == "" {
		return errors.New("missing manifest file specified")
	}
	var fileContent []byte
	if file == "-" {
		fileContent, err = io.ReadAll(cmd.Reader)
	} else {
		fileContent, err = os.ReadFile(file)
	}
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", file, err)
	}
	mediaType := ocispec.DetectMediaType(fileContent)
	desc := ocispec.NewDescriptorFromBytes(mediaType, fileContent)

	cmdhelper.Fprintf(cmd.Writer, `Descriptor:
  - MediaType: %s
  - Digest   : %s
  - Size     : %d
`, desc.MediaType, desc.Digest, desc.Size)

	repository, err := c.NewRepository(ctx, target.Repository())
	if err != nil {
		return err
	}

	for _, tag := range allTags {
		ref, err := name.WithTag(target.Repository(), tag)
		if err != nil {
			return err
		}
		reader := cas.NewReader(bytes.NewReader(fileContent), desc)
		if err := repository.Tags().Tag(ctx, reader, tag); err != nil {
			return err
		}

		cmdhelper.Fprintf(cmd.Writer, "Pushed %s", ref)
	}

	return nil
}

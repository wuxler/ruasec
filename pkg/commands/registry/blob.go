package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/appinfo"
	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands/internal/options"
	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	"github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
	_ "github.com/wuxler/ruasec/pkg/util/xio/compression/builtin"
	"github.com/wuxler/ruasec/pkg/util/xos"
)

// NewBlobCommand returns a BlobCommand with default values.
func NewBlobCommand() *BlobCommand {
	return &BlobCommand{}
}

// BlobCommand defines blob operations.
type BlobCommand struct {
}

// ToCLI transforms to a *cli.Command.
func (c *BlobCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:            "blob",
		Usage:           "Blob operations",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			NewBlobStatCommand().ToCLI(),
			NewBlobFetchCommand().ToCLI(),
			NewBlobDeleteCommand().ToCLI(),
			NewBlobPushCommand().ToCLI(),
		},
	}
}

// NewBlobStatCommand returns a blob stat command with default values.
func NewBlobStatCommand() *BlobStatCommand {
	return &BlobStatCommand{
		Common: options.NewCommonOptions(),
		Remote: options.NewRemoteRegistryOptions(),
	}
}

// BlobStatCommand used to stat the descriptor of the target blob from the remote registry.
type BlobStatCommand struct {
	Common *options.CommonOptions
	Remote *options.RemoteRegistryOptions
}

// Flags defines the flags related to the current command.
func (c *BlobStatCommand) Flags() []cli.Flag {
	flags := []cli.Flag{}
	flags = append(flags, c.Common.Flags()...)
	flags = append(flags, c.Remote.Flags()...)
	return flags
}

// ToCLI transforms to a *cli.Command.
func (c *BlobStatCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "stat",
		Aliases: []string{"desc", "descriptor"},
		Usage:   "Get the descriptor of the target blob",
		UsageText: `rua registry blob stat [OPTIONS] NAME@DIGEST

# Stat the descriptor of the target blob from the remote registry
$ rua registry blob stat hello-world@sha256:c1ec31eb59444d78df06a974d155e597c894ab4cda84f08294145e845394988e
`,
		ArgsUsage: "BLOB",
		Flags:     c.Flags(),
		Action:    c.Run,
	}
}

// Run is the main function for the current command
func (c *BlobStatCommand) Run(ctx context.Context, cmd *cli.Command) error {
	ref := cmd.Args().First()
	target, err := name.NewReference(ref)
	if err != nil {
		return err
	}
	dgstTarget, ok := name.IsDigested(target)
	if !ok {
		return fmt.Errorf("target must be a digest reference formatted as NAME@DIGEST but got %q", ref)
	}

	opts, err := options.MakeDistributionOptions(ctx, c.Common, c.Remote)
	if err != nil {
		return err
	}

	repository, err := remote.NewRepository(ctx, target.Repository(), opts...)
	if err != nil {
		return err
	}

	desc, err := repository.Blobs().Stat(ctx, dgstTarget.Digest().String())
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

// NewBlobFetchCommand returns a blob fetch command with default values.
func NewBlobFetchCommand() *BlobFetchCommand {
	return &BlobFetchCommand{
		Common: options.NewCommonOptions(),
		Remote: options.NewRemoteRegistryOptions(),
	}
}

// BlobFetchCommand used to fetch the blob from the remote registry.
type BlobFetchCommand struct {
	Common *options.CommonOptions
	Remote *options.RemoteRegistryOptions
}

// ToCLI transforms to a *cli.Command.
func (c *BlobFetchCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "fetch",
		Aliases: []string{"get"},
		Usage:   "Get the blob from the remote registry",
		UsageText: `rua registry blob fetch [OPTIONS] NAME@DIGEST

# Fetch raw blob from the remote registry
$ rua registry blob fetch  hello-world@sha256:c1ec31eb59444d78df06a974d155e597c894ab4cda84f08294145e845394988e blob.tar.gz

# Fetch a blob from registry and print the raw blob content
$ rua registry blob fetch hello-world@sha256:c1ec31eb59444d78df06a974d155e597c894ab4cda84f08294145e845394988e - > blob.tar.gz
`,
		ArgsUsage: "BLOB",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(cmdhelper.MinimumNArgs(1)),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *BlobFetchCommand) Flags() []cli.Flag {
	flags := []cli.Flag{}
	flags = append(flags, c.Common.Flags()...)
	flags = append(flags, c.Remote.Flags()...)
	return flags
}

// Run is the main function for the current command
func (c *BlobFetchCommand) Run(ctx context.Context, cmd *cli.Command) error {
	output := cmd.Args().Get(1)
	if output == "" {
		output = "-"
		// Try to guide the user to enter the output file path if the terminal is interactive.
		prompt := promptui.Prompt{
			Label:   `Output file path, use "-" for stdout`,
			Default: "-",
		}
		if input, err := prompt.Run(); err != nil {
			if errors.Is(err, promptui.ErrInterrupt) {
				return err
			}
			cmdhelper.Fprintf(cmd.Writer, "Warninig: It seems the terminal is not interactive, print the raw content to stdout")
		} else if input != "" {
			output = input
		}
	}

	ref := cmd.Args().First()
	target, err := name.NewReference(ref)
	if err != nil {
		return err
	}
	dgstTarget, ok := name.IsDigested(target)
	if !ok {
		return fmt.Errorf("target must be a digest reference formatted as NAME@DIGEST but got %q", ref)
	}

	opts, err := options.MakeDistributionOptions(ctx, c.Common, c.Remote)
	if err != nil {
		return err
	}

	repository, err := remote.NewRepository(ctx, target.Repository(), opts...)
	if err != nil {
		return err
	}

	rc, err := repository.Blobs().FetchDigest(ctx, dgstTarget.Digest())
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)

	var writer io.Writer
	if output == "-" {
		writer = cmd.Writer
	} else {
		// save blob content into the local file if the output path is specified
		file, err := xos.Create(output)
		if err != nil {
			return err
		}
		defer xio.CloseAndSkipError(file)
		writer = file
	}
	if _, err := io.Copy(writer, rc); err != nil {
		return err
	}

	return nil
}

// NewBlobDeleteCommand returns a blob delete command with default values.
func NewBlobDeleteCommand() *BlobDeleteCommand {
	return &BlobDeleteCommand{
		Common: options.NewCommonOptions(),
		Remote: options.NewRemoteRegistryOptions(),
	}
}

// BlobDeleteCommand is used to delete the target blob.
type BlobDeleteCommand struct {
	Common *options.CommonOptions
	Remote *options.RemoteRegistryOptions
	Force  bool `json:"force,omitempty" yaml:"force,omitempty"`
}

// ToCLI transforms to a *cli.Command.
func (c *BlobDeleteCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "delete",
		Aliases: []string{"del", "remove", "rm"},
		Usage:   "Delete the target blob from remote registry",
		UsageText: `rua registry blob delete [OPTIONS] NAME@DIGEST

# Delete the target blob from the remote registry
$ rua registry blob delete hello-world:latest
`,
		ArgsUsage: "BLOB",
		Flags:     c.Flags(),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *BlobDeleteCommand) Flags() []cli.Flag {
	flags := []cli.Flag{
		&cli.BoolFlag{
			Name:        "force",
			Aliases:     []string{"f"},
			Usage:       "force to run, ignore prompt and not found error",
			Destination: &c.Force,
			Value:       c.Force,
		},
	}
	flags = append(flags, c.Common.Flags()...)
	flags = append(flags, c.Remote.Flags()...)
	return flags
}

// Run is the main function for the current command
func (c *BlobDeleteCommand) Run(ctx context.Context, cmd *cli.Command) error {
	ref := cmd.Args().First()
	target, err := name.NewReference(ref)
	if err != nil {
		return err
	}
	dgstTarget, ok := name.IsDigested(target)
	if !ok {
		return fmt.Errorf("target must be a digest reference formatted as NAME@DIGEST but got %q", ref)
	}

	opts, err := options.MakeDistributionOptions(ctx, c.Common, c.Remote)
	if err != nil {
		return err
	}

	repository, err := remote.NewRepository(ctx, target.Repository(), opts...)
	if err != nil {
		return err
	}

	desc, err := repository.Blobs().Stat(ctx, dgstTarget.Digest().String())
	if err != nil {
		if errors.Is(err, errdefs.ErrNotFound) {
			if c.Force {
				// ignore not found error when force flag is set
				cmdhelper.Fprintf(cmd.Writer, "Skip, missing %q which is not found", ref)
				return nil
			}
			return fmt.Errorf("%s: %w", ref, err)
		}
		return err
	}
	cmdhelper.Fprintf(cmd.Writer, `Found %s
  - Digest   : %s
  - Size     : %d
`, target, desc.Digest, desc.Size)

	confirmed := true
	if !c.Force {
		prompt := &promptui.Prompt{
			Label:     "Are you sure to delete the blob",
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

	if err := repository.Blobs().Delete(ctx, desc); err != nil {
		return err
	}
	cmdhelper.Fprintf(cmd.Writer, "Deleted %s", target)
	return nil
}

// NewBlobPushCommand returns a blob push command with default values.
func NewBlobPushCommand() *BlobPushCommand {
	return &BlobPushCommand{
		Remote: options.NewRemoteRegistryOptions(),
		Common: options.NewCommonOptions(),
		Size:   -1,
	}
}

// BlobPushCommand is used to push the target blob.
type BlobPushCommand struct {
	Remote *options.RemoteRegistryOptions
	Common *options.CommonOptions
	Size   int64 `json:"size,omitempty" yaml:"size,omitempty"`
}

// ToCLI transforms to a *cli.Command.
func (c *BlobPushCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "push",
		Usage: "Push the target blob to a remote registry",
		UsageText: `rua registry blob push [OPTIONS] NAME[@DIGEST] FILE

# Push the target blob to a remote registry
$ rua registry blob push hello-world blob.tar.gz

# Push the target blob with specific digest
$ rua registry blob push hello-world@sha256:c1ec31eb59444d78df06a974d155e597c894ab4cda84f08294145e845394988e blob.tar.gz

# Push the target blob from stdin with blob size and digest
$ rua registry blob push --size 2459 hello-world@sha256:c1ec31eb59444d78df06a974d155e597c894ab4cda84f08294145e845394988e -
`,
		ArgsUsage: "BLOB",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(cmdhelper.MinimumNArgs(1)),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *BlobPushCommand) Flags() []cli.Flag {
	flags := []cli.Flag{
		&cli.IntFlag{
			Name:        "size",
			Usage:       "used to validate the size of the blob when reading from stdin",
			Destination: &c.Size,
			Value:       c.Size,
		},
	}
	flags = append(flags, c.Remote.Flags()...)
	flags = append(flags, c.Common.Flags()...)
	return flags
}

// Run is the main function for the current command
func (c *BlobPushCommand) Run(ctx context.Context, cmd *cli.Command) error {
	var target name.Repository
	var dgst digest.Digest
	ref := cmd.Args().First()
	if parsed, err := name.NewReference(ref); err == nil {
		target = parsed.Repository()
		if dgstTarget, ok := name.IsDigested(parsed); ok {
			dgst = dgstTarget.Digest()
		}
	} else if parsed, err := name.NewRepository(ref); err == nil {
		target = parsed
	} else {
		return fmt.Errorf("target must be formatted as NAME[@DIGEST] but got %q", ref)
	}

	opts, err := options.MakeDistributionOptions(ctx, c.Common, c.Remote)
	if err != nil {
		return err
	}

	repository, err := remote.NewRepository(ctx, target, opts...)
	if err != nil {
		return err
	}

	desc, getter, cleanup, err := prepareBlobPushContent(cmd.Args().Get(1), dgst, c.Size)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	cmdhelper.Fprintf(cmd.Writer, `Pushing blob %s
  - Digest   : %s
  - Size     : %d
`, ref, desc.Digest, desc.Size)

	exists, err := repository.Blobs().Exists(ctx, desc)
	if err != nil {
		return err
	}
	if exists {
		cmdhelper.Fprintf(cmd.Writer, "Found blob already exists, skip pushing")
	} else {
		if err := repository.Blobs().Push(ctx, getter); err != nil {
			return err
		}
	}

	cmdhelper.Fprintf(cmd.Writer, "Pushed blob %s", ref)
	return nil
}

func prepareBlobPushContent(path string, dgst digest.Digest, size int64) (desc imgspecv1.Descriptor, getter cas.ReadCloserGetter, cleanup func(), retErr error) {
	var zero imgspecv1.Descriptor
	if path == "" {
		return zero, nil, nil, errors.New("missing file path")
	}
	// read content from stdin
	if path == "-" {
		// read content from stdin and save it to a temporary file
		dir := appinfo.GetWorkspace().TempDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return zero, nil, nil, err
		}
		temp, err := os.CreateTemp(dir, "pushing-blob-*")
		if err != nil {
			return zero, nil, nil, err
		}

		if _, err := io.Copy(temp, os.Stdin); err != nil {
			xio.CloseAndSkipError(temp)
			return zero, nil, nil, err
		}
		xio.CloseAndSkipError(temp)
		// point path to the temporary file
		path = temp.Name()
		cleanup = func() { _ = os.RemoveAll(temp.Name()) }
	}
	defer func() {
		if retErr != nil {
			cleanup()
		}
	}()

	file, err := os.Open(path)
	if err != nil {
		return zero, nil, nil, err
	}
	defer xio.CloseAndSkipError(file)

	fi, err := file.Stat()
	if err != nil {
		return zero, nil, nil, err
	}

	actualSize := fi.Size()
	if size > -1 && size != actualSize {
		return zero, nil, nil, fmt.Errorf("input size %d does not match the actual content size %d", size, actualSize)
	}

	if dgst == "" {
		dgst, err = digest.FromReader(file)
		if err != nil {
			return zero, nil, nil, err
		}
	}

	desc = imgspecv1.Descriptor{
		Digest: dgst,
		Size:   actualSize,
	}
	getter = func(ctx context.Context) (cas.ReadCloser, error) {
		rc, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return cas.NewReadCloser(rc, desc), nil
	}
	return desc, getter, cleanup, nil
}

package options

import (
	"io"
	"net/http"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	"github.com/wuxler/ruasec/pkg/util/xdocker"
)

const (
	// FlagCategoryContainerRegistry is the category name for remote registry flags.
	FlagCategoryContainerRegistry = "[Container Registry]"
)

// NewContainerRegistry returns the options with default values.
func NewContainerRegistry() *ContainerRegistry {
	return &ContainerRegistry{
		Remote:   NewRemote(),
		AuthFile: xdocker.ConfigFile(),
	}
}

// ContainerRegistry defines the remote registry client options.
type ContainerRegistry struct {
	*Remote  `json:",inline" yaml:",inline"`
	AuthFile string `json:"auth_file,omitempty" yaml:"auth_file,omitempty"`
}

// Flags returns the cli flags related to current options.
func (o *ContainerRegistry) Flags() []cli.Flag {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "auth-file",
			Usage:       "registry auth file path",
			Sources:     cli.EnvVars("RUA_REGISTRY_AUTH_FILE"),
			Destination: &o.AuthFile,
			Value:       o.AuthFile,
			Category:    FlagCategoryContainerRegistry,
		},
	}
	flags = append(flags, o.Remote.Flags()...)
	cmdhelper.SetFlagsCategory(FlagCategoryContainerRegistry, flags...)
	return flags
}

// NewClient returns a new remote registry client.
func (o *ContainerRegistry) NewClient(w io.Writer) (*remote.Client, error) {
	tr, err := o.Remote.NewHTTPTransport(w)
	if err != nil {
		return nil, err
	}
	var authProvider remote.AuthProvider
	if o.AuthFile != "" {
		authProvider, err = remote.NewAuthProviderFromAuthFilePath(o.AuthFile)
		if err != nil {
			return nil, err
		}
	}
	client := remote.NewClient()
	client.Client = &http.Client{Transport: tr}
	client.AuthProvider = authProvider
	return client, nil
}

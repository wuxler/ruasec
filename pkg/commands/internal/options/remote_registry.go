package options

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	ocispecremote "github.com/wuxler/ruasec/pkg/ocispec/remote"
	"github.com/wuxler/ruasec/pkg/util/xdocker"
)

const (
	// RemoteRegistryFlagCategory is the category name for remote registry flags.
	RemoteRegistryFlagCategory = "[Remote Registry]"
)

// NewRemoteRegistryOptions returns a *RemoteRegistryOptions with default values.
func NewRemoteRegistryOptions() *RemoteRegistryOptions {
	return &RemoteRegistryOptions{
		AuthFile: xdocker.ConfigFile(),
	}
}

// RemoteRegistryOptions defines the remote registry client options.
type RemoteRegistryOptions struct {
	Insecure bool     `json:"insecure,omitempty" yaml:"insecure,omitempty"`
	CAFiles  []string `json:"ca_files,omitempty" yaml:"ca_files,omitempty"`
	AuthFile string   `json:"auth_file,omitempty" yaml:"auth_file,omitempty"`
}

// Flags returns the []cli.Flag related to current options.
func (o *RemoteRegistryOptions) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "insecure",
			Usage:       "enable to skip verify registry SSL certificate",
			Sources:     cli.EnvVars("RUA_REGISTRY_INSECURE"),
			Destination: &o.Insecure,
			Value:       o.Insecure,
			Category:    RemoteRegistryFlagCategory,
		},
		&cli.StringSliceFlag{
			Name:        "ca-files",
			Usage:       "specify CA files to verify registry SSL certificate",
			Destination: &o.CAFiles,
			Value:       o.CAFiles,
			Validator: func(paths []string) error {
				var errs []error
				for _, path := range paths {
					if _, err := os.ReadFile(path); err != nil {
						errs = append(errs, err)
					}
				}
				return errors.Join(errs...)
			},
			Category: RemoteRegistryFlagCategory,
		},
		&cli.StringFlag{
			Name:        "auth-file",
			Usage:       "registry auth file path",
			Sources:     cli.EnvVars("RUA_REGISTRY_AUTH_FILE"),
			Destination: &o.AuthFile,
			Value:       o.AuthFile,
			Category:    RemoteRegistryFlagCategory,
		},
	}
}

// NewDistributionClient returns a client with options configured.
func (o *RemoteRegistryOptions) NewDistributionClient() (*ocispecremote.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// load tls config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: o.Insecure, //nolint:gosec // explicit skip verify
	}
	if len(o.CAFiles) > 0 {
		if len(o.CAFiles) > 0 {
			pool, err := cmdhelper.LoadTLSCertFiles(o.CAFiles...)
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
	}
	tr.TLSClientConfig = tlsConfig

	client := ocispecremote.NewClient()
	client.Client = &http.Client{Transport: tr}

	if o.AuthFile != "" {
		authProvider, err := ocispecremote.NewAuthProviderFromAuthFilePath(o.AuthFile)
		if err != nil {
			return nil, err
		}
		client.AuthProvider = authProvider
	}
	return client, nil
}

// NewDistributionClient returns distribution remote client options.
func MakeDistributionOptions(ctx context.Context, commonOpts *CommonOptions, remoteOpts *RemoteRegistryOptions) ([]remote.Option, error) {
	client, err := remoteOpts.NewDistributionClient()
	if err != nil {
		return nil, err
	}
	commonOpts.ApplyDistributionClient(client)
	return []remote.Option{remote.WithHTTPClient(client)}, nil
}

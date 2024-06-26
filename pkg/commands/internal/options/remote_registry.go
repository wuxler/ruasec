package options

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/client"
)

// NewRemoteRegistryOptions returns a *RemoteRegistryOptions with default values.
func NewRemoteRegistryOptions() *RemoteRegistryOptions {
	return &RemoteRegistryOptions{
		AuthFile: cmdhelper.DefaultDockerAuthFile(),
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
		},
		&cli.StringFlag{
			Name:        "auth-file",
			Usage:       "registry auth file path",
			Sources:     cli.EnvVars("RUA_REGISTRY_AUTH_FILE"),
			Destination: &o.AuthFile,
			Value:       o.AuthFile,
		},
	}
}

// NewDistributionClientFactory returns a client factory with options configured.
func (o *RemoteRegistryOptions) NewDistributionClientFactory() (*client.Factory, error) {
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

	factory := &client.Factory{
		Client: &http.Client{
			Transport: tr,
		},
	}

	if o.AuthFile != "" {
		authProvider, err := client.NewAuthProviderFromAuthFilePath(o.AuthFile)
		if err != nil {
			return nil, err
		}
		factory.AuthProvider = authProvider
	}
	return factory, nil
}

func (o *RemoteRegistryOptions) NewRegistryClient(ctx context.Context, addr string) (*client.Registry, error) {
	factory, err := o.NewDistributionClientFactory()
	if err != nil {
		return nil, err
	}
	return factory.NewRegistryWithContext(ctx, addr)
}

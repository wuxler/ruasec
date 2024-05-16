package authfile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/smallnest/deepcopy"

	"github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// DockerConfigFile is the ~/.docker/config file info.
// Copy from github.com/docker/cli/cli/config/configfile/file.go
type DockerConfigFile struct {
	AuthConfigs          map[string]authn.AuthConfig  `json:"auths"`
	HTTPHeaders          map[string]string            `json:"HttpHeaders,omitempty"`
	PsFormat             string                       `json:"psFormat,omitempty"`
	ImagesFormat         string                       `json:"imagesFormat,omitempty"`
	NetworksFormat       string                       `json:"networksFormat,omitempty"`
	PluginsFormat        string                       `json:"pluginsFormat,omitempty"`
	VolumesFormat        string                       `json:"volumesFormat,omitempty"`
	StatsFormat          string                       `json:"statsFormat,omitempty"`
	DetachKeys           string                       `json:"detachKeys,omitempty"`
	CredentialsStore     string                       `json:"credsStore,omitempty"`
	CredentialHelpers    map[string]string            `json:"credHelpers,omitempty"`
	ServiceInspectFormat string                       `json:"serviceInspectFormat,omitempty"`
	ServicesFormat       string                       `json:"servicesFormat,omitempty"`
	TasksFormat          string                       `json:"tasksFormat,omitempty"`
	SecretFormat         string                       `json:"secretFormat,omitempty"`
	ConfigFormat         string                       `json:"configFormat,omitempty"`
	NodesFormat          string                       `json:"nodesFormat,omitempty"`
	PruneFilters         []string                     `json:"pruneFilters,omitempty"`
	Proxies              map[string]ProxyConfig       `json:"proxies,omitempty"`
	Experimental         string                       `json:"experimental,omitempty"`
	CurrentContext       string                       `json:"currentContext,omitempty"`
	CLIPluginsExtraDirs  []string                     `json:"cliPluginsExtraDirs,omitempty"`
	Plugins              map[string]map[string]string `json:"plugins,omitempty"`
	Aliases              map[string]string            `json:"aliases,omitempty"`
}

// ProxyConfig contains proxy configuration settings
type ProxyConfig struct {
	HTTPProxy  string `json:"httpProxy,omitempty"`
	HTTPSProxy string `json:"httpsProxy,omitempty"`
	NoProxy    string `json:"noProxy,omitempty"`
	FTPProxy   string `json:"ftpProxy,omitempty"`
	AllProxy   string `json:"allProxy,omitempty"`
}

// NewDockerConfigFile initializes an empty configuration file for the given filename.
func NewDockerConfigFile() *DockerConfigFile {
	return &DockerConfigFile{
		AuthConfigs: make(map[string]authn.AuthConfig),
	}
}

// Erase removes credentials from the store for a given server.
func (c *DockerConfigFile) Erase(_ context.Context, host string) error {
	delete(c.AuthConfigs, host)
	return nil
}

// Get retrieves credentials from the store for a given server.
func (c *DockerConfigFile) Get(_ context.Context, host string) (authn.AuthConfig, error) {
	return c.AuthConfigs[host], nil
}

// GetAll retrieves all the credentials from the store.
func (c *DockerConfigFile) GetAll(ctx context.Context) (map[string]authn.AuthConfig, error) {
	return maps.Clone(c.AuthConfigs), nil
}

// Store saves credentials in the store.
func (c *DockerConfigFile) Store(ctx context.Context, host string, authConfig authn.AuthConfig) error {
	if err := validateCredentialFormat(authConfig); err != nil {
		return err
	}
	c.AuthConfigs[host] = authConfig
	return nil
}

// ContainsAuth returns whether there is authentication configured
// in this file or not.
func (c *DockerConfigFile) ContainsAuth() bool {
	return c.CredentialsStore != "" || len(c.CredentialHelpers) > 0 || len(c.AuthConfigs) > 0
}

// SaveToWriter encodes and writes out all the authorization information to
// the given writer
func (c *DockerConfigFile) SaveToWriter(w io.Writer) error {
	clone := deepcopy.Copy(c)
	for key, value := range clone.AuthConfigs {
		if value.Auth == "" {
			value.Auth = authn.EncodeAuth(value.Username, value.Password)
		}
		value.Username = ""
		value.Password = ""
		clone.AuthConfigs[key] = value
	}
	data, err := json.MarshalIndent(clone, "", "    ")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// SaveToFile encodes and writes out all the authorization information
func (c *DockerConfigFile) SaveToFile(ctx context.Context, filename string) (retErr error) {
	if filename == "" {
		return errors.New("no file name provided on save")
	}
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, filepath.Base(filename))
	if err != nil {
		return err
	}
	defer func() {
		xio.CloseAndSkipError(temp)
		if retErr != nil {
			if err := os.Remove(temp.Name()); err != nil {
				xlog.C(ctx).Debug("unable to cleanup temp file", "file", temp.Name())
			}
		}
	}()
	if err := c.SaveToWriter(temp); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("unable to close temp file: %w", err)
	}
	// Handle situation where the configfile is a symlink
	realpath := filename
	if link, err := os.Readlink(filename); err == nil {
		realpath = link
	}
	// Try copying the current config file (if any) ownership and permissions
	copyFilePermissions(realpath, temp.Name())

	return os.Rename(temp.Name(), realpath)
}

// copyFilePermissions copies file ownership and permissions from "src" to "dst",
// ignoring any error during the process.
func copyFilePermissions(src, dst string) {
	var (
		mode     os.FileMode = 0o600
		uid, gid int
	)

	fi, err := os.Stat(src)
	if err != nil {
		return
	}
	if fi.Mode().IsRegular() {
		mode = fi.Mode()
	}
	if err := os.Chmod(dst, mode); err != nil {
		return
	}

	uid = int(fi.Sys().(*syscall.Stat_t).Uid)
	gid = int(fi.Sys().(*syscall.Stat_t).Gid)

	if uid > 0 && gid > 0 {
		_ = os.Chown(dst, uid, gid) //nolint:errcheck // ignore this error
	}
}

// validateCredentialFormat validates the format of cred.
func validateCredentialFormat(authConfig authn.AuthConfig) error {
	if strings.ContainsRune(authConfig.Username, ':') {
		// Username and password will be encoded in the base64(username:password)
		// format in the file. The decoded result will be wrong if username
		// contains colon(s).
		return fmt.Errorf("%w: colons(:) are not allowed in username", authn.ErrBadCredentialFormat)
	}
	return nil
}

// LoadLegacyDockerConfigFileFromReader implements legacy docker auth config parser which has
// been removed since v23.0.0, see: https://github.com/docker/cli/pull/2504. Here we just copy
// it here for backward capability.
func LoadLegacyDockerConfigFileFromReader(configFile *DockerConfigFile, configData io.Reader) error {
	if configFile == nil {
		return errors.New("configFile is nil")
	}
	data, err := io.ReadAll(configData)
	if err != nil {
		return err
	}
	var errs []error
	if err := parseLegacyDockerConfigFileAsJSON(configFile, data); err != nil {
		errs = append(errs, fmt.Errorf("unable to parse legacy config file as json: %w", err))
	} else {
		return nil
	}
	if err := parseLegacyDockerConfigFileAsPlainText(configFile, data); err != nil {
		errs = append(errs, fmt.Errorf("unable to parse legacy config file as plain text: %w", err))
	} else {
		return nil
	}
	return errors.Join(errs...)
}

func parseLegacyDockerConfigFileAsJSON(configFile *DockerConfigFile, data []byte) error {
	return json.Unmarshal(data, &configFile.AuthConfigs)
}

//nolint:gomnd // ignore magic number lint warning
func parseLegacyDockerConfigFileAsPlainText(configFile *DockerConfigFile, data []byte) error {
	arr := strings.Split(string(data), "\n")
	if len(arr) < 2 {
		return errors.New("the legacy auth config is empty")
	}
	origAuth := strings.Split(arr[0], " = ")
	if len(origAuth) != 2 {
		return errors.New("invalid legacy auth config file")
	}
	username, password, err := authn.DecodeAuth(origAuth[1])
	if err != nil {
		return err
	}
	authConfig := authn.AuthConfig{
		Username: username,
		Password: password,
		Auth:     authn.EncodeAuth(username, password),
	}
	// This constant is only used for really old config files when the
	// URL wasn't saved as part of the config file and it was just
	// assumed to be this value.
	configFile.AuthConfigs[name.DockerIndexServer] = authConfig
	return nil
}

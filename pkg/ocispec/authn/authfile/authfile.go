// Package authfile provides local auth config file operations.
package authfile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/wuxler/ruasec/pkg/ocispec/authn/credentials"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

var (
	_ credentials.Store = (*AuthFile)(nil)
)

// NewAuthFile returns a new auth config file with the given filename.
func NewAuthFile(filename string) *AuthFile {
	return &AuthFile{
		DockerConfigFile: NewDockerConfigFile(),
		filename:         filename,
	}
}

// NewLegacyAuthFile returns a legacy auth config file with the given filename.
func NewLegacyAuthFile(filename string) *AuthFile {
	f := NewAuthFile(filename)
	f.isLegacy = true
	return f
}

// AuthFile is a local auth docker config file.
type AuthFile struct {
	*DockerConfigFile `json:",inline"`

	filename string `json:"-"` // Note: for internal use only
	// isLegacy presents the target auth config file is old format.
	isLegacy bool `json:"-"`
}

// Load reads and decodes the auth config file.
func (f *AuthFile) Load() error {
	cfgFile, err := os.Open(f.filename)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(cfgFile)

	if !f.isLegacy {
		err = json.NewDecoder(cfgFile).Decode(f.DockerConfigFile)
	} else {
		err = LoadLegacyDockerConfigFileFromReader(f.DockerConfigFile, cfgFile)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse auth file %q: %w", f.filename, err)
	}
	return nil
}

// Save encodes and writes out all the authorization information.
func (f *AuthFile) Save(ctx context.Context) error {
	return f.DockerConfigFile.SaveToFile(ctx, f.filename)
}

// GetCredentialsStore returns a new credentials store from the settings in the
// configuration file
func (f *AuthFile) GetCredentialsStore() credentials.Store {
	return credentials.NewFileStore(f)
}

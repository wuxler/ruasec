// Package appinfo defines application build informations and runtime configures.
package appinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pre-defined variables set by LDFLAGS like below:
//
//	go build -ldflags '-X github.com/wuxler/ruasec/pkg/appinfo.version=v1.0.0'
var (
	// version value from regexp capture in gitBranch or gitTag
	version = "dev"
	// buildDate output from `date -u +'%Y-%m-%dT%H:%M:%SZ'`
	buildDate = "1970-01-01T00:00:00Z"
	// gitBranch output from `git rev-parse --symbolic-full-name --verify --quiet --abbrev-ref HEAD`
	gitBranch = ""
	// gitCommit output from `git rev-parse HEAD`
	gitCommit = ""
	// gitTag output from `git describe --exact-match --tags HEAD` (if clean tree state)
	gitTag = ""
	// gitTreeState determined from `git status --porcelain`. either 'clean' or 'dirty'
	gitTreeState = ""
)

// Version records the application's version information, including the
// application version, Git information at build time, and environment
// information.
type Version struct {
	Version string    `json:"version" yaml:"version"`
	Git     GitInfo   `json:"git" yaml:"git"`
	Build   BuildInfo `json:"build" yaml:"build"`
}

// GitInfo records the git informations at build time.
type GitInfo struct {
	Branch    string `json:"branch" yaml:"branch"`
	Commit    string `json:"commit" yaml:"commit"`
	Tag       string `json:"tag" yaml:"tag"`
	TreeState string `json:"tree_state" yaml:"tree_state"`
}

// BuildInfo records the build informations.
type BuildInfo struct {
	BuildDate string `json:"build_date,omitempty" yaml:"build_date,omitempty"`
	GoVersion string `json:"go_version,omitempty" yaml:"go_version,omitempty"`
	Compiler  string `json:"compiler,omitempty" yaml:"compiler,omitempty"`
	OS        string `json:"os,omitempty" yaml:"os,omitempty"`
	Arch      string `json:"arch,omitempty" yaml:"arch,omitempty"`
	Platform  string `json:"platform,omitempty" yaml:"platform,omitempty"`
}

// GetVersion returns the Version of the application.
func GetVersion() Version {
	return Version{
		Version: version,
		Git: GitInfo{
			Branch:    gitBranch,
			Commit:    gitCommit,
			Tag:       gitTag,
			TreeState: gitTreeState,
		},
		Build: BuildInfo{
			BuildDate: buildDate,
			GoVersion: runtime.Version(),
			Compiler:  runtime.Compiler,
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		},
	}
}

// ShortVersion returns the short version string.
func ShortVersion() string {
	if gitCommit != "" && len(gitCommit) > 7 {
		return version + "-" + gitCommit[0:8]
	}
	return version
}

// NewVersionWriter returns *VersionWriter which wrapped with Version.
func NewVersionWriter(v Version) *VersionWriter {
	return &VersionWriter{
		version: v,
	}
}

// VersionWriter wraps Version to provides helpful methods.
type VersionWriter struct {
	version Version

	short   bool
	format  string
	appName string
}

// SetShort is a chain methods to set short options.
func (vw *VersionWriter) SetShort(short bool) *VersionWriter {
	vw.short = short
	return vw
}

// SetFormat is a chian methods to set format options.
func (vw *VersionWriter) SetFormat(format string) *VersionWriter {
	vw.format = format
	return vw
}

// SetAppName is a chian methods to set application name options.
func (vw *VersionWriter) SetAppName(name string) *VersionWriter {
	vw.appName = name
	return vw
}

// Version returns wrapped Version object.
func (vw VersionWriter) Version() Version {
	return vw.version
}

// Write will write version information with options into io.Writer
// and return error when failed.
func (vw VersionWriter) Write(w io.Writer) error {
	switch strings.ToLower(vw.format) {
	case "yaml", "yml":
		return yaml.NewEncoder(w).Encode(vw.version)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(vw.version)
	}
	if vw.short {
		_, err := fmt.Fprintln(w, vw.ShortLine())
		return err
	}
	_, err := fmt.Fprintf(w, "%s", vw.Extended())
	return err
}

// Line is a helpful methods to return one-line version string with application
// name if set.
func (vw VersionWriter) Line() string {
	s := vw.ShortLine()
	if vw.appName != "" {
		s = vw.appName + " " + s
	}
	return s
}

// ShortLine is a helpful methods to return one-line version string.
func (vw VersionWriter) ShortLine() string {
	v := vw.Version()
	s := v.Version
	if v.Git.Commit != "" {
		s += " (" + v.Git.Commit + ")"
	}
	return s
}

// Extended is a helpful methods to return multiple lines version string.
func (vw VersionWriter) Extended() string {
	v := vw.version
	var s string
	if vw.appName != "" {
		s += fmt.Sprintf("Application  : %s\n", vw.appName)
	}
	s += fmt.Sprintf(`Version      : %s
[Git]
  Branch     : %s
  Commit     : %s
  Tag        : %s
  TreeState  : %s
[Build]
  BuildDate  : %s
  GoVersion  : %s
  Compiler   : %s
  Platform   : %s
`,
		v.Version, v.Git.Branch, v.Git.Commit, v.Git.Tag, v.Git.TreeState,
		v.Build.BuildDate, v.Build.GoVersion, v.Build.Compiler, v.Build.Platform)
	return s
}

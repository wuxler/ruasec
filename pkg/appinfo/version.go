package appinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pre-defined varaibles set by LDFLAGS like below:
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
	Version string    `json:"version"`
	Git     GitInfo   `json:"git"`
	Build   BuildInfo `json:"build"`
}

// GitInfo records the git informations at build time.
type GitInfo struct {
	Branch    string `json:"branch,omitempty"`
	Commit    string `json:"commit"`
	Tag       string `json:"tag"`
	TreeState string `json:"treeState"`
}

// BuildInfo records the build informations.
type BuildInfo struct {
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	Compiler  string `json:"compiler"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Platform  string `json:"platform"`
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

func NewVersionWriter(v Version) *VersionWriter {
	return &VersionWriter{
		version: v,
	}
}

type VersionWriter struct {
	version Version

	short   bool
	format  string
	appName string
}

func (vw *VersionWriter) SetShort(short bool) *VersionWriter {
	vw.short = short
	return vw
}

func (vw *VersionWriter) SetFormat(format string) *VersionWriter {
	vw.format = format
	return vw
}

func (vw *VersionWriter) SetAppName(name string) *VersionWriter {
	vw.appName = name
	return vw
}

func (vw VersionWriter) Version() Version {
	return vw.version
}

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

func (vw VersionWriter) Line() string {
	s := vw.ShortLine()
	if vw.appName != "" {
		s = vw.appName + " " + s
	}
	return s
}

func (vw VersionWriter) ShortLine() string {
	v := vw.Version()
	s := v.Version
	if v.Git.Commit != "" {
		s += " (" + v.Git.Commit + ")"
	}
	return s
}

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

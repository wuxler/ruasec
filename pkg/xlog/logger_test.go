package xlog_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wuxler/ruasec/pkg/xlog"
)

func TestLogger_SetLevel(t *testing.T) {
	stdout := &bytes.Buffer{}
	c := xlog.NewConfig()
	c.AttrReplacer = xlog.ChainReplacer(
		xlog.NormalizeSourceAttrReplacer(),
		xlog.SuppressTimeAttrReplacer(),
	)
	c.StdWriter = stdout

	xlog.SetDefault(xlog.New(c))

	xlog.Debug("log message with attrs", "attr1", "val1", "attr2", "val2")
	xlog.Debugf("log message with format: %s", "hello")
	xlog.SetLevel(xlog.LevelDebug)
	xlog.Debug("log message with attrs", "attr1", "val1", "attr2", "val2")
	xlog.Debugf("log message with format: %s", "hello")

	got := stdout.String()
	want := strings.TrimLeft(`
level=DEBUG source=logger_test.go:27 msg="log message with attrs" attr1=val1 attr2=val2
level=DEBUG source=logger_test.go:28 msg="log message with format: hello"
`, "\n")

	assert.Equal(t, got, want)
}

func TestLogger_FileHandler(t *testing.T) {
	stdout := &bytes.Buffer{}
	tempdir := t.TempDir()

	c := xlog.NewConfig()
	c.AttrReplacer = xlog.ChainReplacer(
		xlog.NormalizeSourceAttrReplacer(),
		xlog.SuppressTimeAttrReplacer(),
	)
	c.StdWriter = stdout
	c.Path = filepath.Join(tempdir, "x.log")

	xlog.SetDefault(xlog.New(c))

	xlog.Info("log message with attrs", "attr1", "val1", "attr2", "val2")
	xlog.Infof("log message with format: %s", "hello")
	xlog.Debug("log message with attrs", "attr1", "val1", "attr2", "val2")
	xlog.Debugf("log message with format: %s", "hello")
	xlog.SetLevel(xlog.LevelDebug)
	xlog.Debug("log message with attrs", "attr1", "val1", "attr2", "val2")
	xlog.Debugf("log message with format: %s", "hello")

	t.Run("stdout", func(t *testing.T) {
		want := strings.TrimLeft(`
level=INFO source=logger_test.go:55 msg="log message with attrs" attr1=val1 attr2=val2
level=INFO source=logger_test.go:56 msg="log message with format: hello"
level=DEBUG source=logger_test.go:60 msg="log message with attrs" attr1=val1 attr2=val2
level=DEBUG source=logger_test.go:61 msg="log message with format: hello"
`, "\n")
		assert.Equal(t, stdout.String(), want)
	})

	t.Run("logfile", func(t *testing.T) {
		content, err := os.ReadFile(c.Path)
		require.NoError(t, err)
		want := strings.TrimLeft(`
{"level":"INFO","source":{"function":"github.com/wuxler/ruasec/pkg/xlog_test.TestLogger_FileHandler","file":"logger_test.go","line":55},"msg":"log message with attrs","attr1":"val1","attr2":"val2"}
{"level":"INFO","source":{"function":"github.com/wuxler/ruasec/pkg/xlog_test.TestLogger_FileHandler","file":"logger_test.go","line":56},"msg":"log message with format: hello"}
{"level":"DEBUG","source":{"function":"github.com/wuxler/ruasec/pkg/xlog_test.TestLogger_FileHandler","file":"logger_test.go","line":60},"msg":"log message with attrs","attr1":"val1","attr2":"val2"}
{"level":"DEBUG","source":{"function":"github.com/wuxler/ruasec/pkg/xlog_test.TestLogger_FileHandler","file":"logger_test.go","line":61},"msg":"log message with format: hello"}
`, "\n")
		assert.Equal(t, want, string(content))
	})
}

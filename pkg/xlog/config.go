package xlog

import (
	"io"
	"log/slog"
	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

// NewConfig 返回默认日志配置
func NewConfig() Config {
	return Config{
		Level:        slog.LevelInfo,
		AddSource:    true,
		AttrReplacer: NormalizeSourceAttrReplacer(),
		StdFormat:    "text",
		StdWriter:    os.Stdout,
		Path:         "",
		MaxSize:      30,
		MaxAge:       0,
		MaxBackups:   0,
		Compress:     false,
	}
}

// Config 日志配置
type Config struct {
	// Level 日志输出级别, 默认为 LevelInfo
	Level slog.Level
	// AddSource 是否输出日志所在文件和位置
	AddSource bool
	// AttrReplacer 重写特定属性, 默认 BasenameSourceAttrReplacer
	AttrReplacer AttrReplacer

	// StdFormat 标准输出的格式, 可选值: ["text", "json"]
	StdFormat string
	// StdWriter 标准输出的 io.Writer, 默认为 os.Stdout
	StdWriter io.Writer

	// Path 日志文件路径, 如果为空表示不输出日志到文件
	Path string
	// MaxSize 单个日志文件最大体积, 单位为 MB, 超过该大小自动切分, 默认为 30 MB
	MaxSize int
	// MaxAge 日志文件最多保留的天数, 默认一直保留
	MaxAge int
	// MaxBackups 日志文件最多保留的个数, 默认一直保留
	MaxBackups int
	// Compress 是否压缩切片的日志文件, 默认不压缩
	Compress bool
}

// BuildHandler creates a new slog.Handler with config.
func (c *Config) BuildHandler() slog.Handler {
	opts := c.buildHandlerOptions()
	if c.StdFormat == "json" {
		writer := c.StdWriter
		if fw := c.buildFileWriter(); fw != nil {
			writer = io.MultiWriter(c.StdWriter, c.buildFileWriter())
		}
		return NewLeveledHandlerCreator(JSONHandlerCreator)(writer, opts)
	}

	// console output format as "text"
	handlers := []slog.Handler{}

	stdHandler := NewLeveledHandlerCreator(TextHandlerCreator)(c.StdWriter, opts)
	handlers = append(handlers, stdHandler)

	if fw := c.buildFileWriter(); fw != nil {
		fileHandler := NewLeveledHandlerCreator(JSONHandlerCreator)(fw, opts)
		handlers = append(handlers, fileHandler)
	}
	return MultiHandler(handlers...)
}

func (c *Config) buildFileWriter() io.Writer {
	if c.Path == "" {
		// 未设置日志文件路径
		return nil
	}
	return &lumberjack.Logger{
		Filename:   c.Path,
		MaxSize:    c.MaxSize,
		MaxAge:     c.MaxAge,
		MaxBackups: c.MaxBackups,
		Compress:   c.Compress,
	}
}

func (c *Config) buildHandlerOptions() *slog.HandlerOptions {
	return &slog.HandlerOptions{
		AddSource:   c.AddSource,
		Level:       c.Level,
		ReplaceAttr: c.AttrReplacer,
	}
}

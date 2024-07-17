package compression

import (
	"fmt"
	"maps"
	"strings"
	"sync"
)

var (
	formats = make(map[string]Format)
	mu      sync.RWMutex
)

// RegisterFormat registers a format. It should be called during init().
// Duplicate formats by name are not allowed and will return error.
func RegisterFormat(format Format) error {
	mu.Lock()
	defer mu.Unlock()

	name := cleanFormatName(format.Name())
	if _, ok := formats[name]; ok {
		return fmt.Errorf("format %q is already registered", name)
	}
	formats[name] = format
	return nil
}

// MustRegisterFormat registers a format and will panic when duplicate format
// registered occurred.
func MustRegisterFormat(format Format) {
	if err := RegisterFormat(format); err != nil {
		panic(err)
	}
}

// GetFormat returns a format by name provided and an error will be returned
// when no format found.
func GetFormat(name string) (Format, error) {
	mu.RLock()
	defer mu.RUnlock()

	name = cleanFormatName(name)
	if format, ok := formats[name]; ok {
		return format, nil
	}
	return nil, fmt.Errorf("not found any format with %q", name)
}

// MustGetFormat returns a format by name provided and will panic when no
// format found.
func MustGetFormat(name string) Format {
	format, err := GetFormat(name)
	if err != nil {
		panic(err)
	}
	return format
}

// AllFormats returns the clone of all registered formats map.
func AllFormats() map[string]Format {
	mu.RLock()
	defer mu.RUnlock()

	return maps.Clone(formats)
}

func cleanFormatName(name string) string {
	return strings.Trim(strings.ToLower(name), ".")
}

package cmdhelper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Fprintf is a wrapper around fmt.Fprintf to suppress the error check.
func Fprintf(w io.Writer, format string, args ...any) {
	if format[len(format)-1] != '\n' {
		format += "\n"
	}
	_, _ = fmt.Fprintf(w, format, args...)
}

// PrettifyJSON is a helper function to prettify data to json bytes with indents.
func PrettifyJSON(data any) ([]byte, error) {
	switch v := data.(type) {
	case []byte:
		return prettifyJSONBytes(v)
	case string:
		return prettifyJSONBytes([]byte(v))
	default:
		return json.MarshalIndent(data, "", "  ")
	}
}

func prettifyJSONBytes(data []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := json.Indent(buf, data, "", "  "); err != nil {
		return nil, fmt.Errorf("failed to prettify: %w", err)
	}
	return buf.Bytes(), nil
}

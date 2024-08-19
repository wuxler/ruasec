package xos

// Forked from https://github.com/moby/moby/blob/v27.1.2/pkg/system/xattrs.go

// XattrError is an error returned by xattr operations.
type XattrError struct {
	Op   string
	Attr string
	Path string
	Err  error
}

func (e *XattrError) Error() string { return e.Op + " " + e.Attr + " " + e.Path + ": " + e.Err.Error() }

func (e *XattrError) Unwrap() error { return e.Err }

// Timeout reports whether this error represents a timeout.
func (e *XattrError) Timeout() bool {
	t, ok := e.Err.(interface{ Timeout() bool })
	return ok && t.Timeout()
}

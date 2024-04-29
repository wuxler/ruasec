package xio

import (
	"errors"
	"io"
	"strings"

	"github.com/wuxler/ruasec/pkg/xlog"
)

// CloseAndSkipError is used to close the io.Closer and ignore the error returned.
func CloseAndSkipError(c io.Closer) {
	if c != nil {
		_ = c.Close()
	}
}

// CloseAndLogError is used to close the io.Closer and log out as warning when the error
// returned is not nil.
// You are recommended to use this function to fix errcheck lint warning. For example
// "defer CloseAndLogError(rc)" instead	of "defer rc.Close()".
func CloseAndLogError(c io.Closer, messages ...string) {
	var msg string
	if len(messages) > 0 {
		msg = strings.Join(messages, ": ")
	}

	err := c.Close()
	if err == nil {
		return
	}

	if msg == "" {
		xlog.Warnf("unable to close: %+v", err)
		return
	}
	xlog.Warnf("unable to close: %s: %+v", msg, err)
}

// MultiClosers returns an io.Closer that is the logical concatenation of the provided
// closers list. All of the provided closers will be call the Close() method, even if
// any returned an error.
func MultiClosers(closers ...io.Closer) io.Closer {
	return multiClosers(closers)
}

type multiClosers []io.Closer

// Close implements io.Closer and closes all the closers.
func (mc multiClosers) Close() error {
	var errs []error
	for _, closer := range mc {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

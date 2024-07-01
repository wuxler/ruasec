package errdefs

import "errors"

var (
	// ErrNotFound signals that the requested object doesn't exist.
	ErrNotFound = errors.New("not found")

	// ErrInvalidParameter signals that the user input is invalid.
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrConflict signals that some internal state conflicts with the requested action
	// and can't be performed. A change in state should be able to clear this error.
	ErrConflict = errors.New("conflict")

	// ErrUnauthorized is used to signify that the user is not authorized to perform a
	// specific action
	ErrUnauthorized = errors.New("unauthorized")

	// ErrUnavailable signals that the requested action/subsystem is not available.
	ErrUnavailable = errors.New("unavailable")

	// ErrForbidden signals that the requested action cannot be performed under any circumstances.
	// When a ErrForbidden is returned, the caller should never retry the action.
	ErrForbidden = errors.New("forbidden")

	// ErrSystem signals that some internal error occurred.
	// An example of this would be a failed mount request.
	ErrSystem = errors.New("system error")

	// ErrNotImplemented signals that the requested action/feature is not implemented on the system as configured.
	ErrNotImplemented = errors.New("not implemented")

	// ErrUnknown signals that the kind of error that occurred is not known.
	ErrUnknown = errors.New("unknown error")

	// ErrCanceled signals that the action was canceled.
	ErrCanceled = errors.New("canceled")

	// ErrDeadline signals that the deadline was reached before the action completed.
	ErrDeadlineExceeded = errors.New("deadline exceeded")

	// ErrDataLoss indicates that data was lost or there is data corruption.
	ErrDataLoss = errors.New("data loss")

	// ErrAlreadyExists signals that resources is already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrUnsupported indicates that the action was not supported.
	ErrUnsupported = errors.New("unsupported")

	// ErrUnsupportedVersion indicates that target version was not supported.
	ErrUnsupportedVersion = errors.New("unsupported version")
)

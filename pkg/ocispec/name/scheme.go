package name

import (
	"sync"

	"github.com/samber/lo"
)

var (
	schemes     = map[string]struct{}{}
	schemesLock sync.Mutex
)

// RegisterScheme registers a scheme.
func RegisterScheme(scheme string) {
	schemesLock.Lock()
	defer schemesLock.Unlock()
	_, ok := schemes[scheme]
	if ok {
		panic("scheme already registered: " + scheme)
	}
	schemes[scheme] = struct{}{}
}

// IsRegisteredScheme returns true if the scheme is registered.
func IsRegisteredScheme(scheme string) bool {
	schemesLock.Lock()
	defer schemesLock.Unlock()
	_, ok := schemes[scheme]
	return ok
}

// AllRegisteredSchemes returns a list of all registered schemes.
func AllRegisteredSchemes() []string {
	schemesLock.Lock()
	defer schemesLock.Unlock()
	return lo.Keys(schemes)
}

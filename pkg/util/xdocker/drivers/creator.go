package drivers

import (
	"context"
	"fmt"
	"sync"

	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
)

var (
	creators = make(map[Type]Creator)
	mu       sync.RWMutex
)

// Creator is the interface for the backend storage driver creator.
type Creator interface {
	// Create creates a new driver instance.
	Create(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (Driver, error)
}

// CreatorFunc is a function that implements the DriverCreator interface.
type CreatorFunc func(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (Driver, error)

// Create creates a new driver instance.
func (fn CreatorFunc) Create(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (Driver, error) {
	return fn(ctx, dataRoot, options)
}

// RegisterCreator registers a driver creator.
func RegisterCreator(typ Type, creator Creator) error {
	mu.Lock()
	defer mu.Unlock()

	if _, ok := creators[typ]; ok {
		return fmt.Errorf("storage driver creator with %q already registered", typ)
	}
	creators[typ] = creator
	return nil
}

// MustRegisterCreator registers a driver creator and panics on error.
func MustRegisterCreator(typ Type, creator Creator) {
	if err := RegisterCreator(typ, creator); err != nil {
		panic(err)
	}
}

// GetCreator returns the driver creator for the given type.
// If none is found, it returns nil and false.
func GetCreator(typ Type) (Creator, bool) {
	mu.RLock()
	defer mu.RUnlock()

	creator, ok := creators[typ]
	return creator, ok
}

// SupportedTypes returns all of the supported driver types.
func SupportedTypes() Types {
	mu.RLock()
	defer mu.RUnlock()

	return lo.Keys(creators)
}

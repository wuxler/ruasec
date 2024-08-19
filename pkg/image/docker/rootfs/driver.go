package rootfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/util/xos"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// Driver is the interface for the backend storage driver.
type Driver interface {
	// Type returns the type of the driver
	Type() DriverType
	// Accessible returns true when the target exists and accessible with the given cache id.
	// If the target does not exist, it returns false with nil error.
	// If the target is not accessible, it returns false with an error.
	Accessible(cacheid string) (bool, error)
	// GetMetadata returns the metadata of the target with the given cache id.
	GetMetadata(cacheid string) (map[string]string, error)
}

// DifferDriver is a driver that can provide a differ with the given cache id.
type DifferDriver interface {
	// GetDiffer returns a differ for the target with the given cache id.
	GetDiffer(cacheid string) (ocispec.FSGetter, error)
}

// DriverCreator is the interface for the backend storage driver creator.
type DriverCreator interface {
	// Create creates a new driver instance.
	Create(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (Driver, error)
}

// DriverCreatorFunc is a function that implements the DriverCreator interface.

type DriverCreatorFunc func(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (Driver, error)

// Create creates a new driver instance.
func (fn DriverCreatorFunc) Create(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (Driver, error) {
	return fn(ctx, dataRoot, options)
}

var (
	driverCreators = make(map[DriverType]DriverCreator)
	driverMu       sync.RWMutex
)

// RegisterDriverCreator registers a driver creator.
func RegisterDriverCreator(typ DriverType, creator DriverCreator) error {
	driverMu.Lock()
	defer driverMu.Unlock()

	if _, ok := driverCreators[typ]; ok {
		return fmt.Errorf("storage driver creator with %q already registered", typ)
	}
	driverCreators[typ] = creator
	return nil
}

// MustRegisterDriverCreator registers a driver creator and panics on error.
func MustRegisterDriverCreator(typ DriverType, creator DriverCreator) {
	if err := RegisterDriverCreator(typ, creator); err != nil {
		panic(err)
	}
}

// GetDriverCreator returns the driver creator for the given type.
// If none is found, it returns nil and false.
func GetDriverCreator(typ DriverType) (DriverCreator, bool) {
	driverMu.RLock()
	defer driverMu.RUnlock()

	creator, ok := driverCreators[typ]
	return creator, ok
}

// SupportedDriverTypes returns all of the supported driver types.
func SupportedDriverTypes() DriverTypes {
	driverMu.RLock()
	defer driverMu.RUnlock()

	return lo.Keys(driverCreators)
}

// NewDriver creates a new driver instance.
func NewDriver(ctx context.Context, path string, typ DriverType, config DriverConfig) (Driver, error) {
	ctx = xlog.WithContext(ctx, "root", path, "driver", typ.String())
	creator, ok := GetDriverCreator(typ)
	if !ok {
		return nil, errdefs.Newf(errdefs.ErrUnsupported, "driver type %q is not supported", typ)
	}
	root := pathspec.DataRoot(path)
	return creator.Create(ctx, root, config.Options)
}

// FindSupportedDriverTypes finds supported driver types in the given path.
// If the driver directory is not accessible or is empty, it will be skipped.
func FindSupportedDriverTypes(ctx context.Context, path string) map[DriverType]bool {
	found := map[DriverType]bool{}
	for _, typ := range SupportedDriverTypes() {
		dir := filepath.Join(path, string(typ))
		ok, err := xos.Exists(dir)
		if err != nil {
			xlog.C(ctx).Warnf("skip, unable to check if %s exists: %v", dir, err)
			continue
		}
		if ok && !xos.IsEmptyDir(dir) {
			found[typ] = true
		}
	}
	return found
}

// LookupPriorDriverType looks up the prior driver type to use for the given path.
func LookupPriorDriverType(ctx context.Context, path string) (DriverType, bool) {
	found := FindSupportedDriverTypes(ctx, path)
	for _, prior := range priorityDriverTypes {
		if prior == DriverTypeVfs {
			// skip vfs
			continue
		}
		if !found[prior] {
			continue
		}
		if len(found) > 1 {
			foundTypes := DriverTypes(lo.Keys(found))
			xlog.C(ctx).Infof("more than 1 driver [%s] found, using prior one: %s",
				strings.Join(foundTypes.ToStrings(), ", "), prior)
		}
		if IsDeprecatedDriverType(prior) {
			xlog.C(ctx).Warnf("using deprecated driver type: %s", prior)
		}
		return prior, true
	}
	return "", false
}

// DetectDriverType detects the driver type from the runtime environment.
func DetectDriverType(ctx context.Context, path string) DriverType {
	// TODO: from /etc/docker/daemon.json
	// from environment variable
	typ := DriverType(os.Getenv("DOCKER_DRIVER"))
	if typ != "" {
		if _, ok := GetDriverCreator(typ); ok {
			xlog.C(ctx).Debugf("discovered driver from the env $DOCKER_DRIVER: %s", typ)
			return typ
		}
	}
	// from docker data root lookup
	if !xos.IsEmptyDir(path) {
		if found, ok := LookupPriorDriverType(ctx, path); ok {
			xlog.C(ctx).Debugf("discovered driver from the docker data root: %s", found)
			return found
		}
	}
	return ""
}

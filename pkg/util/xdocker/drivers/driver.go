package drivers

import (
	"context"
	"os"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/util/xos"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// Driver is the interface for the backend storage driver.
type Driver interface {
	// Type returns the type of the driver
	Type() Type
	// Accessible returns true when the target exists and accessible with the given cache id.
	// If the target does not exist, it returns false with nil error.
	// If the target is not accessible, it returns false with an error.
	Accessible(cacheid string) (bool, error)
	// GetMetadata returns the metadata of the target with the given cache id.
	GetMetadata(cacheid string) (map[string]string, error)
}

// DriverConfig is the config used to create a backend storage driver.
type DriverConfig struct {
	Options []string
}

// New creates a new driver instance.
func New(ctx context.Context, path string, typ Type, config DriverConfig) (Driver, error) {
	ctx = xlog.WithContext(ctx, "root", path, "driver", typ.String())
	creator, ok := GetCreator(typ)
	if !ok {
		return nil, errdefs.Newf(errdefs.ErrUnsupported, "driver type %q is not supported", typ)
	}
	root := pathspec.DataRoot(path)
	return creator.Create(ctx, root, config.Options)
}

// DetectType detects the driver type from the runtime environment.
func DetectType(ctx context.Context, path string) Type {
	// TODO: from /etc/docker/daemon.json
	// from environment variable
	typ := Type(os.Getenv("DOCKER_DRIVER"))
	if typ != "" {
		if _, ok := GetCreator(typ); ok {
			xlog.C(ctx).Debugf("discovered driver from the env $DOCKER_DRIVER: %s", typ)
			return typ
		}
	}
	// from docker data root lookup
	if !xos.IsEmptyDir(path) {
		if found, ok := LookupPriorType(ctx, path); ok {
			xlog.C(ctx).Debugf("discovered driver from the docker data root: %s", found)
			return found
		}
	}
	return ""
}

package overlay2

import (
	"context"
	"strings"

	"github.com/spf13/cast"

	"github.com/wuxler/ruasec/pkg/util/xdocker/drivers"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/util/xfs"
	"github.com/wuxler/ruasec/pkg/util/xos"
)

var (
	_ drivers.Differ = (*Driver)(nil)
)

func init() {
	drivers.MustRegisterCreator(drivers.TypeOverlay2, drivers.CreatorFunc(New))
}

// New creates a new overlay2 driver
func New(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (drivers.Driver, error) {
	return &Driver{
		DriverRoot: dataRoot.DriverRoot(drivers.TypeOverlay2.String()),
	}, nil
}

// Driver is a driver for overlay2
type Driver struct {
	pathspec.DriverRoot
}

// Type returns the type of the driver
func (d *Driver) Type() drivers.Type {
	return drivers.TypeOverlay2
}

// Accessible returns true when the target exists and accessible with the given cache id.
// If the target does not exist, it returns false with nil error.
// If the target is not accessible, it returns false with an error.
func (d *Driver) Accessible(cacheid string) (bool, error) {
	return xos.Exists(d.entityTo(cacheid).Path())
}

// GetMetadata returns the metadata of the target with the given cache id.
func (d *Driver) GetMetadata(cacheid string) (map[string]string, error) {
	ent := d.entityTo(cacheid)
	readonly, err := ent.IsReadonly()
	if err != nil {
		return nil, err
	}
	lowers, err := ent.GetLowerPaths()
	if err != nil {
		return nil, err
	}
	metadata := map[string]string{
		"WorkDir":   ent.WorkDir(),
		"MergedDir": ent.MergedDir(),
		"UpperDir":  ent.DiffDir(),
		"ReadOnly":  cast.ToString(readonly),
		"LowerDir":  strings.Join(lowers, ":"),
	}
	return metadata, nil
}

// Diff returns a differ for the target with the given cache id.
func (d *Driver) Diff(cacheid string) (xfs.Getter, error) {
	return d.entityTo(cacheid), nil
}

func (d *Driver) entityTo(cacheid string) *entity {
	return &entity{
		Driver:  d,
		cacheid: cacheid,
	}
}

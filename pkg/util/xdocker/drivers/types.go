package drivers

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/util/xos"
	"github.com/wuxler/ruasec/pkg/xlog"
)

const (
	TypeOverlay2      Type = "overlay2"
	TypeOverlay       Type = "overlay"
	TypeFuseOverlayfs Type = "fuse-overlayfs"
	TypeBtrfs         Type = "btrfs"
	TypeZfs           Type = "zfs"
	TypeAufs          Type = "aufs"
	TypeDevicemapper  Type = "devicemapper"
	TypeVfs           Type = "vfs"
	// windows
	TypeWindowsFilter Type = "windowsfilter"
)

var (
	// list of driver types in order of priority
	priorityTypes = Types{
		TypeOverlay2,
		TypeFuseOverlayfs,
		TypeBtrfs,
		TypeZfs,
		TypeAufs,
		TypeOverlay,
		TypeDevicemapper,
		TypeVfs,
	}
	knownDeprecatedTypes = Types{
		TypeAufs,
		TypeDevicemapper,
		TypeOverlay,
	}
)

// Type is the type of docker storage driver supported.
type Type string

// String returns the string representation of the driver type.
func (t Type) String() string {
	return string(t)
}

// Types is a list of driver types.
type Types []Type

// String returns the string representation of the driver types list.
func (ts Types) String() string {
	return strings.Join(ts.ToStrings(), ", ")
}

// ToStrings converts the driver types list to a slice of strings.
func (ts Types) ToStrings() []string {
	ss := []string{}
	for _, t := range ts {
		ss = append(ss, t.String())
	}
	return ss
}

// IsDeprecatedType returns true if the driver type is marked "deprecated" and not recommended for use
// explicitly by Docker official.
func IsDeprecatedType(typ Type) bool {
	return lo.Contains(knownDeprecatedTypes, typ)
}

// FindSupportedTypes finds supported driver types in the given path.
// If the driver directory is not accessible or is empty, it will be skipped.
func FindSupportedTypes(ctx context.Context, path string) map[Type]bool {
	found := map[Type]bool{}
	for _, typ := range SupportedTypes() {
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

// LookupPriorType looks up the prior driver type to use for the given path.
func LookupPriorType(ctx context.Context, path string) (Type, bool) {
	found := FindSupportedTypes(ctx, path)
	for _, prior := range priorityTypes {
		if prior == TypeVfs {
			// skip vfs
			continue
		}
		if !found[prior] {
			continue
		}
		if len(found) > 1 {
			foundTypes := Types(lo.Keys(found))
			xlog.C(ctx).Infof("more than 1 driver [%s] found, using prior one: %s",
				strings.Join(foundTypes.ToStrings(), ", "), prior)
		}
		if IsDeprecatedType(prior) {
			xlog.C(ctx).Warnf("using deprecated driver type: %s", prior)
		}
		return prior, true
	}
	return "", false
}

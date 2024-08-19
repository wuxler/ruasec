package rootfs

import (
	"strings"

	"github.com/samber/lo"
)

const (
	DriverTypeOverlay2      DriverType = "overlay2"
	DriverTypeOverlay       DriverType = "overlay"
	DriverTypeFuseOverlayfs DriverType = "fuse-overlayfs"
	DriverTypeBtrfs         DriverType = "btrfs"
	DriverTypeZfs           DriverType = "zfs"
	DriverTypeAufs          DriverType = "aufs"
	DriverTypeDevicemapper  DriverType = "devicemapper"
	DriverTypeVfs           DriverType = "vfs"
	// windows
	DriverTypeWindowsFilter DriverType = "windowsfilter"
)

var (
	// list of driver types in order of priority
	priorityDriverTypes = DriverTypes{
		DriverTypeOverlay2,
		DriverTypeFuseOverlayfs,
		DriverTypeBtrfs,
		DriverTypeZfs,
		DriverTypeAufs,
		DriverTypeOverlay,
		DriverTypeDevicemapper,
		DriverTypeVfs,
	}
	knownDeprecatedDriverTypes = DriverTypes{
		DriverTypeAufs,
		DriverTypeDevicemapper,
		DriverTypeOverlay,
	}
)

// DriverType is the type of docker storage driver supported.
type DriverType string

// String returns the string representation of the driver type.
func (t DriverType) String() string {
	return string(t)
}

// DriverTypes is a list of driver types.
type DriverTypes []DriverType

// String returns the string representation of the driver types list.
func (ts DriverTypes) String() string {
	return strings.Join(ts.ToStrings(), ", ")
}

// ToStrings converts the driver types list to a slice of strings.
func (ts DriverTypes) ToStrings() []string {
	ss := []string{}
	for _, t := range ts {
		ss = append(ss, t.String())
	}
	return ss
}

// IsDeprecatedDriverType returns true if the driver type is marked "deprecated" and not recommended for use
// explicitly by Docker official.
func IsDeprecatedDriverType(typ DriverType) bool {
	return lo.Contains(knownDeprecatedDriverTypes, typ)
}

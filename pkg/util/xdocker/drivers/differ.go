package drivers

import "github.com/wuxler/ruasec/pkg/util/xfs"

// Differ is a driver that can provide a differ with the given cache id.
type Differ interface {
	// Diff returns a diff filesystem getter for the target with the given cache id.
	Diff(cacheid string) (xfs.Getter, error)
}

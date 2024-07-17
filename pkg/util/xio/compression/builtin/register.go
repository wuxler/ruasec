// Package builtin registers all built-in compression algorithms.
package builtin

import (
	_ "github.com/wuxler/ruasec/pkg/util/xio/compression/bz2"  // register bz2 compression
	_ "github.com/wuxler/ruasec/pkg/util/xio/compression/gzip" // register gzip compression
	_ "github.com/wuxler/ruasec/pkg/util/xio/compression/tar"  // register tar compression
	_ "github.com/wuxler/ruasec/pkg/util/xio/compression/xz"   // register xz compression
	_ "github.com/wuxler/ruasec/pkg/util/xio/compression/zstd" // register zstd compression
)

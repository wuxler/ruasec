// Package all registers all builtin image manifest schema implements.
package all

import (
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/dockerschema1" // register docker schema 1
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/dockerschema2" // register docker schema 2
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/ocischema"     // register oci schema
)

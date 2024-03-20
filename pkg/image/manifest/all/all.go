// Package all registers all the image manifest schema implements.
package all

import (
	_ "github.com/wuxler/ruasec/pkg/image/manifest/dockerschema1" // register docker schema 1
	_ "github.com/wuxler/ruasec/pkg/image/manifest/dockerschema2" // register docker schema 2
	_ "github.com/wuxler/ruasec/pkg/image/manifest/ocischema"     // register oci schema
)

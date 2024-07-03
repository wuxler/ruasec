package manifest

import (
	"fmt"
	"mime"
	"sync"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
)

// UnmarshalFunc implements manifest unmarshalling a given MediaType
type UnmarshalFunc func([]byte) (ocispec.Manifest, imgspecv1.Descriptor, error)

var (
	schemas = make(map[string]UnmarshalFunc)
	mu      sync.RWMutex
)

// RegisterSchema registers an UnmarshalFunc for a given schema type. This should be
// called from specific.
func RegisterSchema(mediaType string, fn UnmarshalFunc) error {
	mu.Lock()
	defer mu.Unlock()

	if _, ok := schemas[mediaType]; ok {
		return fmt.Errorf("manifest media type registration is already existed: %s", mediaType)
	}
	schemas[mediaType] = fn
	return nil
}

// MustRegisterSchema registers an UnmarshalFunc for a given schema type
// and will panic when error is not nil.
func MustRegisterSchema(mediaType string, fn UnmarshalFunc) {
	if err := RegisterSchema(mediaType, fn); err != nil {
		panic(fmt.Errorf("unable to register schema: %w", err))
	}
}

// GetSchema looks up manifest unmarshal functions based on MediaType.
//
// NOTE: mediaType may be Content-Type value string in http Header.
func GetSchema(mediaType string) (UnmarshalFunc, error) {
	var err error
	if mediaType != "" {
		mediaType, _, err = mime.ParseMediaType(mediaType)
		if err != nil {
			return nil, err
		}
	}

	mu.RLock()
	defer mu.RUnlock()

	fn, ok := schemas[mediaType]
	if ok {
		return fn, nil
	}
	if defaultFn, ok := schemas[""]; ok {
		return defaultFn, nil
	}
	return nil, fmt.Errorf("unsupported manifest media type and no default availabel: %q", mediaType)
}

// MustGetSchema looks up manifest unmarshal functions based on MediaType
// and will panic when error is not nil.
func MustGetSchema(mediaType string) UnmarshalFunc {
	fn, err := GetSchema(mediaType)
	if err != nil {
		panic(fmt.Errorf("schema not found: %w", err))
	}
	return fn
}

// AllSupportedMediaTypes returns all supported media types for manifests.
func AllSupportedMediaTypes() []string {
	mu.RLock()
	defer mu.RUnlock()

	mts := []string{}
	for mt := range schemas {
		if mt != "" {
			mts = append(mts, mt)
		}
	}
	return mts
}

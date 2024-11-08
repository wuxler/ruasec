package cmdhelper

import (
	"crypto/x509"
	"fmt"
	"os"
	"reflect"

	"github.com/urfave/cli/v3"
)

// LoadTLSCertFiles creates and loads all cert files with the paths specified.
func LoadTLSCertFiles(paths ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, path := range paths {
		pemCerts, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if ok := pool.AppendCertsFromPEM(pemCerts); !ok {
			return nil, fmt.Errorf("unable to append certs from pem file %s: %w", path, err)
		}
	}
	return pool, nil
}

// SetFlagsCategory sets the category for the given flags.
func SetFlagsCategory(category string, flags ...cli.Flag) {
	for _, flag := range flags {
		// NOTE: maybe panic here when:
		//  * flag is not a pointer to a struct
		//  * flag does not contains a "Category" field
		//  * flag.Category is not a string type field
		reflect.ValueOf(flag).Elem().FieldByName("Category").SetString(category)
	}
}

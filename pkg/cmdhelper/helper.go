package cmdhelper

import (
	"crypto/x509"
	"fmt"
	"os"
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

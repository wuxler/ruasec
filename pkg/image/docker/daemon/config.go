package daemon

import (
	"os"
	"time"
)

const (
	DefaultDialTimeout = 30 * time.Second
)

type Config struct {
	Host        string
	CacheDir    string
	DialTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		CacheDir:    os.TempDir(),
		DialTimeout: DefaultDialTimeout,
	}
}

package distribution_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
)

func TestRegistry_Ping(t *testing.T) {
	c, err := distribution.DefaultClient.NewRegistry("https://" + name.DefaultRegistry)
	require.NoError(t, err)
	err = c.Ping(context.Background())
	assert.NoError(t, err)
}

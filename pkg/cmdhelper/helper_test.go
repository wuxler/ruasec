package cmdhelper

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v3"
)

func Test_applyFlag(t *testing.T) {
	flag1 := &cli.BoolFlag{
		Name:     "flag1",
		Local:    true,
		Category: "",
	}
	flag2 := &cli.StringFlag{
		Name:     "flag2",
		Category: "common",
	}
	flags := []cli.Flag{flag1, flag2}

	for _, flag := range flags {
		applyFlag(flag)
	}
	assert.Equal(t, "common", flag1.Category)
	assert.True(t, flag2.Local)
}

func applyFlag(flag cli.Flag) {
	reflect.ValueOf(flag).Elem().FieldByName("Category").SetString("common")
	reflect.ValueOf(flag).Elem().FieldByName("Local").SetBool(true)
}

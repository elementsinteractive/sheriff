package cli

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestPatrolActionEmptyRun(t *testing.T) {
	context := cli.NewContext(cli.NewApp(), flag.NewFlagSet("flagset", flag.ContinueOnError), nil)

	err := PatrolAction(context)

	assert.Nil(t, err)
}

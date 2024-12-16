package cli

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestPatrolActionEmptyRun(t *testing.T) {
	// Monkey patch necessaryScanners to avoid missing scanners
	// during testing
	origNecessaryScanners := necessaryScanners
	necessaryScanners = []string{}
	defer func() {
		necessaryScanners = origNecessaryScanners
	}()

	context := cli.NewContext(cli.NewApp(), flag.NewFlagSet("flagset", flag.ContinueOnError), nil)

	err := PatrolAction(context)

	assert.Nil(t, err)
}

func TestGetMissingScanners(t *testing.T) {
	testCases := []struct {
		scanners []string
		want     []string
	}{
		{[]string{"ls", "missing"}, []string{"missing"}},
		{[]string{"echo", "ls", "missing", "missing-another"}, []string{"missing", "missing-another"}},
		{[]string{"ls"}, []string{}},
	}

	for _, tc := range testCases {
		missingScanners := getMissingScanners(tc.scanners)

		assert.Equal(t, tc.want, missingScanners)
	}
}

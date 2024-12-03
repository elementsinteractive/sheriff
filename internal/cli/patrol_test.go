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

func TestValidatePathGroupPathRegex(t *testing.T) {
	testCases := []struct {
		paths []string
		want  bool
	}{
		{[]string{"group"}, true},
		{[]string{"group/subgroup"}, true},
		{[]string{"group/subgroup", "not a path"}, false},
	}

	for _, tc := range testCases {
		err := validatePaths(groupPathRegex)(nil, tc.paths)

		if tc.want {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}
	}
}

func TestValidatePathProjectPathRegex(t *testing.T) {
	testCases := []struct {
		paths []string
		want  bool
	}{
		{[]string{"project"}, false}, // top-level projects don't exist
		{[]string{"group/project"}, true},
		{[]string{"group/project", "not a path"}, false},
	}

	for _, tc := range testCases {
		err := validatePaths(projectPathRegex)(nil, tc.paths)

		if tc.want {
			assert.Nil(t, err, tc.paths)
		} else {
			assert.NotNil(t, err, tc.paths)
		}
	}
}

func TestValidateUrl(t *testing.T) {

	testCases := []struct {
		urls []string
		want bool
	}{
		{[]string{"gitlab://example.com"}, true},
	}

	for _, tc := range testCases {
		err := validateURLs(nil, tc.urls)

		if tc.want {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}
	}
}

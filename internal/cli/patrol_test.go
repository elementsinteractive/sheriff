package cli

import (
	"flag"
	"sheriff/internal/patrol"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestPatrolActionEmptyRun(t *testing.T) {
	context := cli.NewContext(cli.NewApp(), flag.NewFlagSet("flagset", flag.ContinueOnError), nil)

	err := PatrolAction(context)

	assert.Nil(t, err)
}

func TestParseURLs(t *testing.T) {
	testCases := []struct {
		urls           []string
		validPlatforms []string
		wantErr        bool
		wantResult     *[]patrol.GenericUrlElem
	}{
		{
			urls:           []string{"gitlab://gitlab.com/namespace/group"},
			validPlatforms: sourceCodePlatforms,
			wantErr:        false,
			wantResult: &[]patrol.GenericUrlElem{
				{
					Platform: "gitlab",
					Url:      "gitlab.com/namespace/group",
				},
			},
		},
		{
			urls:           []string{"gitlab://gitlab.com/namespace/group", "azure://not-supported.com"},
			validPlatforms: sourceCodePlatforms,
			wantErr:        true,
			wantResult:     nil,
		},
		{
			urls:           []string{"slack://channel1", "slack://channel2", "issue://"},
			validPlatforms: reportToPlatforms,
			wantErr:        false,
			wantResult: &[]patrol.GenericUrlElem{
				{
					Platform: "slack",
					Url:      "channel1",
				},
				{
					Platform: "slack",
					Url:      "channel2",
				},
				{
					Platform: "issue",
					Url:      "",
				},
			},
		},
	}

	for _, tc := range testCases {
		result, err := parseURLs(tc.urls)

		if tc.wantErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, tc.wantResult, result)
		}
	}
}

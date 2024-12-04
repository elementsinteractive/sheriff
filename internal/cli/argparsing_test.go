package cli

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseURLs(t *testing.T) {
	testCases := []struct {
		urls           []string
		validPlatforms []string
		wantErr        bool
		wantResult     []*url.URL
	}{
		{
			urls:           []string{"gitlab://gitlab.com/namespace/group"},
			validPlatforms: sourceCodePlatforms,
			wantErr:        false,
			wantResult: []*url.URL{
				{
					Scheme: "gitlab",
					Host:   "gitlab.com",
					Path:   "/namespace/group",
				},
			},
		},
		{
			urls:           []string{"gitlab://gitlab.com/namespace/group", "azure://not-supported.com"},
			validPlatforms: sourceCodePlatforms,
			wantErr:        true,
			wantResult:     make([]*url.URL, 0),
		},
		{
			urls:           []string{"slack://channel1", "slack://channel2", "issue://"},
			validPlatforms: reportToPlatforms,
			wantErr:        false,
			wantResult: []*url.URL{
				{
					Scheme: "slack",
					Host:   "channel1",
				},
				{
					Scheme: "slack",
					Host:   "channel2",
				},
				{
					Scheme: "issue",
					Host:   "",
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

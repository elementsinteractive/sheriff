package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUrls(t *testing.T) {
	testCases := []struct {
		paths               []string
		wantProjectLocation *ProjectLocation
		wantError           bool
	}{
		{[]string{"gitlab://namespace/project"}, &ProjectLocation{Type: "gitlab", Path: "namespace/project"}, false},
		{[]string{"gitlab://namespace/subgroup/project"}, &ProjectLocation{Type: "gitlab", Path: "namespace/subgroup/project"}, false},
		{[]string{"gitlab://namespace"}, &ProjectLocation{Type: "gitlab", Path: "namespace"}, false},
		{[]string{"github://organization"}, &ProjectLocation{Type: "github", Path: "organization"}, true},
		{[]string{"github://organization/project"}, &ProjectLocation{Type: "github", Path: "organization/project"}, true},
		{[]string{"unknown://namespace/project"}, nil, true},
		{[]string{"unknown://not a path"}, nil, true},
		{[]string{"not a url"}, nil, true},
	}

	for _, tc := range testCases {
		urls, err := parseUrls(tc.paths)

		fmt.Print(urls)

		if tc.wantError {
			assert.NotNil(t, err)
		} else {
			assert.Equal(t, tc.wantProjectLocation, &(urls[0]))
		}
	}
}

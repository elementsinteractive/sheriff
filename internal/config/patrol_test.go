package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPatrolConfiguration(t *testing.T) {
	want := PatrolConfig{
		Locations:             []ProjectLocation{{Type: Gitlab, Path: "group1"}, {Type: Gitlab, Path: "group2/project1"}},
		ReportToEmails:        []string{"some-email@gmail.com"},
		ReportToSlackChannel:  "report-slack-channel",
		ReportToIssue:         true,
		EnableProjectReportTo: true,
		SilentReport:          true,
		Verbose:               true,
	}

	got, err := GetPatrolConfiguration(PatrolCLIOpts{
		Config:  "testdata/patrol/valid.toml",
		Verbose: true,
	})

	assert.Nil(t, err)
	assert.Equal(t, want, got)
}

func TestGetPatrolConfigurationCLIOverridesFile(t *testing.T) {
	want := PatrolConfig{
		Locations:             []ProjectLocation{{Type: Gitlab, Path: "group1"}, {Type: Gitlab, Path: "group2/project1"}},
		ReportToEmails:        []string{"email@gmail.com", "other@gmail.com"},
		ReportToSlackChannel:  "other-slack-channel",
		ReportToIssue:         false,
		EnableProjectReportTo: false, // Here we test overriding with a zero-value, which works!
		SilentReport:          false,
		Verbose:               true,
	}

	got, err := GetPatrolConfiguration(PatrolCLIOpts{
		Config:  "testdata/patrol/valid.toml",
		Verbose: true,
		PatrolCommonOpts: PatrolCommonOpts{
			Urls: &[]string{"gitlab://group1", "gitlab://group2/project1"},
			Report: PatrolReportOpts{
				To: PatrolReportToOpts{
					Emails:                &want.ReportToEmails,
					SlackChannel:          &want.ReportToSlackChannel,
					Issue:                 &want.ReportToIssue,
					EnableProjectReportTo: &want.EnableProjectReportTo,
				},
				SilentReport: &want.SilentReport,
			},
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, want, got)
}

func TestGetPatrolConfigurationInvalidFile(t *testing.T) {
	_, err := GetPatrolConfiguration(PatrolCLIOpts{
		Config:  "testdata/patrol/invalid.toml",
		Verbose: true,
	})

	assert.NotNil(t, err)
}

func TestGetPatrolConfigurationInexistentFile(t *testing.T) {
	_, err := GetPatrolConfiguration(PatrolCLIOpts{
		Config:  "testdata/patrol/inexistent.toml",
		Verbose: true,
	})

	assert.NotNil(t, err)
}

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

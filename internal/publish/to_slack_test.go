package publish

import (
	"sheriff/internal/config"
	"sheriff/internal/scanner"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gogitlab "github.com/xanzy/go-gitlab"
)

func TestPublishAsGeneralSlackMessage(t *testing.T) {
	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return("", nil)
	report := []scanner.Report{
		{
			IsVulnerable: true,
			Vulnerabilities: []scanner.Vulnerability{
				{
					Id: "CVE-2021-1234",
				},
			},
		},
	}

	err := PublishAsGeneralSlackMessage([]string{"channel"}, report, []string{"path/to/group", "path/to/project"}, mockSlackService)

	assert.Nil(t, err)
	mockSlackService.AssertExpectations(t)
}

func TestPublishAsGeneralSlackMessageToMultipleChannel(t *testing.T) {
	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel1", mock.Anything).Return("", nil)
	mockSlackService.On("PostMessage", "channel2", mock.Anything).Return("", nil)
	report := []scanner.Report{
		{
			IsVulnerable: true,
			Vulnerabilities: []scanner.Vulnerability{
				{
					Id: "CVE-2021-1234",
				},
			},
		},
	}

	err := PublishAsGeneralSlackMessage([]string{"channel1", "channel2"}, report, []string{"path/to/group", "path/to/project"}, mockSlackService)

	assert.Nil(t, err)
	mockSlackService.AssertExpectations(t)
}

func TestPublishAsSpecificChannelSlackMessage(t *testing.T) {
	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return("", nil)
	report := scanner.Report{
		IsVulnerable: true,
		Vulnerabilities: []scanner.Vulnerability{
			{
				Id: "CVE-2021-1234",
			},
		},
		ProjectConfig: config.ProjectConfig{ReportToSlackChannel: "channel"},
	}

	_ = PublishAsSpecificChannelSlackMessage([]scanner.Report{report}, mockSlackService)

	mockSlackService.AssertExpectations(t)
	mockSlackService.AssertNumberOfCalls(t, "PostMessage", 1)
}

func TestFormatSummary(t *testing.T) {
	report := []scanner.Report{
		{
			IsVulnerable: true,
			Vulnerabilities: []scanner.Vulnerability{
				{
					Id:                "CVE-2021-1234",
					SeverityScoreKind: scanner.Critical,
				},
				{
					Id:                "CVE-2021-1235",
					SeverityScoreKind: scanner.High,
				},
			},
		},
		{
			IsVulnerable:    false,
			Vulnerabilities: []scanner.Vulnerability{},
		},
	}

	msgOpts := formatSummary(groupVulnReportsByMaxSeverityKind(report), len(report), []string{"path/to/group", "path/to/project"})

	assert.NotNil(t, msgOpts)
	assert.Len(t, msgOpts, 1)
}

func TestFormatReportMessage(t *testing.T) {
	reportBySeverityKind := map[scanner.SeverityScoreKind][]scanner.Report{
		scanner.Critical: {
			{
				Project: gogitlab.Project{
					Name:   "project1",
					WebURL: "http://example.com",
				},

				IsVulnerable: true,
				Vulnerabilities: []scanner.Vulnerability{
					{
						Id:                "CVE-2021-1234",
						SeverityScoreKind: scanner.Critical,
					},
				},
			},
		},
		scanner.High: {
			{
				Project: gogitlab.Project{
					Name:   "project2",
					WebURL: "http://example2.com",
				},
				IsVulnerable: true,
				Vulnerabilities: []scanner.Vulnerability{
					{
						Id:                "CVE-2021-1235",
						SeverityScoreKind: scanner.High,
					},
				},
			},
		},
	}

	formatted := formatReportMessage(reportBySeverityKind)

	assert.NotNil(t, formatted)
	assert.Len(t, formatted, 1)
}

func TestSplitMessage(t *testing.T) {
	testCases := map[string][]string{
		// Case with no newlines at all, simply split by maxLen
		"This is a test message": {"This is a ", "test messa", "ge"},
		// Case with newline, will split by it even if it's not at maxLen
		"This is a\ntest message": {"This is a\n", "test messa", "ge"},
		// Case with multiple newlines
		"This is\n a test\nmessage\n": {"This is\n", " a test\n", "message\n"},
	}

	for input, want := range testCases {
		got := splitMessage(input, 10)
		assert.Equal(t, want, got)
	}

}

type mockSlackService struct {
	mock.Mock
}

func (c *mockSlackService) PostMessage(channelName string, options ...slack.MsgOption) (string, error) {
	args := c.Called(channelName, options)
	return args.String(0), args.Error(1)
}

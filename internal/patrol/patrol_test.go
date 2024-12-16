package patrol

import (
	"sheriff/internal/config"
	"sheriff/internal/scanner"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xanzy/go-gitlab"
)

func TestNewService(t *testing.T) {
	s := New(&mockGitlabService{}, &mockSlackService{}, &mockGitService{}, &mockOSVService{})

	assert.NotNil(t, s)
}

func TestScanNoProjects(t *testing.T) {
	mockGitlabService := &mockGitlabService{}
	mockGitlabService.On("GetProjectList", []string{"group/to/scan"}).Return([]gitlab.Project{}, nil)

	mockSlackService := &mockSlackService{}

	mockGitService := &mockGitService{}
	mockGitService.On("Clone", mock.Anything, "https://gitlab.com/group/to/scan.git").Return(nil)

	mockOSVService := &mockOSVService{}
	mockOSVService.On("Scan", mock.Anything).Return(&scanner.OsvReport{}, nil)

	svc := New(mockGitlabService, mockSlackService, mockGitService, mockOSVService)

	warn, err := svc.Patrol(config.PatrolConfig{
		Locations:             []config.ProjectLocation{{Type: config.Gitlab, Path: "group/to/scan"}},
		ReportToEmails:        []string{},
		ReportToSlackChannel:  "channel",
		ReportToIssue:         true,
		EnableProjectReportTo: true,
		Verbose:               true,
		SilentReport:          false,
	})

	assert.Nil(t, err)
	assert.Nil(t, warn)
	mockGitlabService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

func TestScanNonVulnerableProject(t *testing.T) {
	mockGitlabService := &mockGitlabService{}
	mockGitlabService.On("GetProjectList", []string{"group/to/scan"}).Return([]gitlab.Project{{Name: "Hello World", HTTPURLToRepo: "https://gitlab.com/group/to/scan.git"}}, nil)
	mockGitlabService.On("CloseVulnerabilityIssue", mock.Anything).Return(nil)

	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return("", nil)

	mockGitService := &mockGitService{}
	mockGitService.On("Clone", mock.Anything, "https://gitlab.com/group/to/scan.git").Return(nil)

	mockOSVService := &mockOSVService{}
	mockOSVService.On("Scan", mock.Anything).Return(&scanner.OsvReport{}, nil)
	mockOSVService.On("GenerateReport", mock.Anything, mock.Anything).Return(scanner.Report{})

	svc := New(mockGitlabService, mockSlackService, mockGitService, mockOSVService)

	warn, err := svc.Patrol(config.PatrolConfig{
		Locations:             []config.ProjectLocation{{Type: config.Gitlab, Path: "group/to/scan"}},
		ReportToEmails:        []string{},
		ReportToSlackChannel:  "channel",
		ReportToIssue:         true,
		EnableProjectReportTo: true,
		Verbose:               true,
		SilentReport:          false,
	})

	assert.Nil(t, err)
	assert.Nil(t, warn)
	mockGitlabService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

func TestScanVulnerableProject(t *testing.T) {
	mockGitlabService := &mockGitlabService{}
	mockGitlabService.On("GetProjectList", []string{"group/to/scan"}).Return([]gitlab.Project{{Name: "Hello World", HTTPURLToRepo: "https://gitlab.com/group/to/scan.git"}}, nil)
	mockGitlabService.On("OpenVulnerabilityIssue", mock.Anything, mock.Anything).Return(&gitlab.Issue{}, nil)

	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return("", nil)

	mockGitService := &mockGitService{}
	mockGitService.On("Clone", mock.Anything, "https://gitlab.com/group/to/scan.git").Return(nil)

	mockOSVService := &mockOSVService{}
	report := &scanner.OsvReport{}
	mockOSVService.On("Scan", mock.Anything).Return(report, nil)
	mockOSVService.On("GenerateReport", mock.Anything, mock.Anything).Return(scanner.Report{
		IsVulnerable: true,
		Vulnerabilities: []scanner.Vulnerability{
			{
				Id: "CVE-2021-1234",
			},
		},
	})

	svc := New(mockGitlabService, mockSlackService, mockGitService, mockOSVService)

	warn, err := svc.Patrol(config.PatrolConfig{
		Locations:             []config.ProjectLocation{{Type: config.Gitlab, Path: "group/to/scan"}},
		ReportToEmails:        []string{},
		ReportToSlackChannel:  "channel",
		ReportToIssue:         true,
		EnableProjectReportTo: true,
		Verbose:               true,
		SilentReport:          false,
	})

	assert.Nil(t, err)
	assert.Nil(t, warn)
	mockGitlabService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

func TestMarkVulnsAsAcknowledgedInReport(t *testing.T) {
	report := scanner.Report{
		Vulnerabilities: []scanner.Vulnerability{
			{
				Id:                "CVE-1",
				SeverityScoreKind: scanner.Critical,
			},

			{
				Id:                "CVE-2",
				SeverityScoreKind: scanner.Critical,
			},
		},
	}
	config := config.ProjectConfig{
		Acknowledged: []config.AcknowledgedVuln{
			{
				Code:   "CVE-1",
				Reason: "This is a reason",
			},

			{
				Code: "CVE-3", // not in report
			},
		},
	}

	markVulnsAsAcknowledgedInReport(&report, config)

	assert.Equal(t, scanner.Acknowledged, report.Vulnerabilities[0].SeverityScoreKind)
	assert.Equal(t, "This is a reason", report.Vulnerabilities[0].AckReason)
	assert.Equal(t, scanner.Critical, report.Vulnerabilities[1].SeverityScoreKind)
}

type mockGitlabService struct {
	mock.Mock
}

func (c *mockGitlabService) GetProjectList(paths []string) ([]gitlab.Project, error) {
	args := c.Called(paths)
	return args.Get(0).([]gitlab.Project), args.Error(1)
}

func (c *mockGitlabService) CloseVulnerabilityIssue(project gitlab.Project) error {
	args := c.Called(project)
	return args.Error(0)
}

func (c *mockGitlabService) OpenVulnerabilityIssue(project gitlab.Project, report string) (*gitlab.Issue, error) {
	args := c.Called(project, report)
	return args.Get(0).(*gitlab.Issue), args.Error(1)
}

type mockSlackService struct {
	mock.Mock
}

func (c *mockSlackService) PostMessage(channelName string, options ...slack.MsgOption) (string, error) {
	args := c.Called(channelName, options)
	return args.String(0), args.Error(1)
}

type mockGitService struct {
	mock.Mock
}

func (c *mockGitService) Clone(dir string, url string) (err error) {
	args := c.Called(dir, url)
	return args.Error(0)
}

type mockOSVService struct {
	mock.Mock
}

func (c *mockOSVService) Scan(dir string) (*scanner.OsvReport, error) {
	args := c.Called(dir)
	return args.Get(0).(*scanner.OsvReport), args.Error(1)
}

func (c *mockOSVService) GenerateReport(p gitlab.Project, r *scanner.OsvReport) scanner.Report {
	args := c.Called(p, r)
	return args.Get(0).(scanner.Report)
}

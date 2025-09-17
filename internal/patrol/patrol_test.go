package patrol

import (
	"sheriff/internal/config"
	"sheriff/internal/repository"
	"sheriff/internal/scanner"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewService(t *testing.T) {
	s := New(&mockRepoService{}, &mockSlackService{}, &mockOSVService{})

	assert.NotNil(t, s)
}

func TestScanNoProjects(t *testing.T) {
	mockClient := &mockClient{}
	mockClient.On("GetProjectList", []string{"group/to/scan"}).Return([]repository.Project{}, nil)

	mockRepoService := &mockRepoService{}
	mockRepoService.On("Provide", repository.Gitlab).Return(mockClient)

	mockSlackService := &mockSlackService{}

	mockOSVService := &mockOSVService{}
	mockOSVService.On("Scan", mock.Anything).Return(&scanner.OsvReport{}, nil)

	svc := New(mockRepoService, mockSlackService, mockOSVService)

	warn, err := svc.Patrol(config.PatrolConfig{
		Locations:             []config.ProjectLocation{{Type: repository.Gitlab, Path: "group/to/scan"}},
		ReportToEmails:        []string{},
		ReportToSlackChannels: []string{"channel"},
		ReportToIssue:         true,
		EnableProjectReportTo: true,
		Verbose:               true,
		SilentReport:          false,
	})

	assert.Nil(t, err)
	assert.Nil(t, warn)
	mockClient.AssertExpectations(t)
	mockRepoService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

func TestScanNonVulnerableProject(t *testing.T) {
	mockClient := &mockClient{}
	mockClient.On("GetProjectList", []string{"group/to/scan"}).Return([]repository.Project{{Name: "Hello World", RepoUrl: "https://gitlab.com/group/to/scan.git", Repository: repository.Gitlab}}, nil)
	mockClient.On("CloseVulnerabilityIssue", mock.Anything).Return(nil)
	mockClient.On("Clone", "https://gitlab.com/group/to/scan.git", mock.Anything).Return(nil)

	mockRepoService := &mockRepoService{}
	mockRepoService.On("Provide", repository.Gitlab).Return(mockClient)

	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return("", nil)

	mockOSVService := &mockOSVService{}
	mockOSVService.On("Scan", mock.Anything).Return(&scanner.OsvReport{}, nil)
	mockOSVService.On("GenerateReport", mock.Anything, mock.Anything).Return(scanner.Report{Project: repository.Project{Repository: repository.Gitlab}})

	svc := New(mockRepoService, mockSlackService, mockOSVService)

	warn, err := svc.Patrol(config.PatrolConfig{
		Locations:             []config.ProjectLocation{{Type: repository.Gitlab, Path: "group/to/scan"}},
		ReportToEmails:        []string{},
		ReportToSlackChannels: []string{"channel"},
		ReportToIssue:         true,
		EnableProjectReportTo: true,
		Verbose:               true,
		SilentReport:          false,
	})

	assert.Nil(t, err)
	assert.Nil(t, warn)
	mockClient.AssertExpectations(t)
	mockRepoService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

func TestScanVulnerableProject(t *testing.T) {
	mockClient := &mockClient{}
	mockClient.On("GetProjectList", []string{"group/to/scan"}).Return([]repository.Project{{Name: "Hello World", RepoUrl: "https://gitlab.com/group/to/scan.git", Repository: repository.Gitlab}}, nil)
	mockClient.On("OpenVulnerabilityIssue", mock.Anything, mock.Anything).Return(&repository.Issue{}, nil)
	mockClient.On("Clone", "https://gitlab.com/group/to/scan.git", mock.Anything).Return(nil)

	mockRepoService := &mockRepoService{}
	mockRepoService.On("Provide", repository.Gitlab).Return(mockClient)

	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return("", nil)

	mockOSVService := &mockOSVService{}
	report := &scanner.OsvReport{}
	mockOSVService.On("Scan", mock.Anything).Return(report, nil)
	mockOSVService.On("GenerateReport", mock.Anything, mock.Anything).Return(scanner.Report{
		Project:      repository.Project{Repository: repository.Gitlab},
		IsVulnerable: true,
		Vulnerabilities: []scanner.Vulnerability{
			{
				Id: "CVE-2021-1234",
			},
		},
	})

	svc := New(mockRepoService, mockSlackService, mockOSVService)

	warn, err := svc.Patrol(config.PatrolConfig{
		Locations:             []config.ProjectLocation{{Type: repository.Gitlab, Path: "group/to/scan"}},
		ReportToEmails:        []string{},
		ReportToSlackChannels: []string{"channel"},
		ReportToIssue:         true,
		EnableProjectReportTo: true,
		Verbose:               true,
		SilentReport:          false,
	})

	assert.Nil(t, err)
	assert.Nil(t, warn)
	mockClient.AssertExpectations(t)
	mockRepoService.AssertExpectations(t)
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

func TestMarkOutdatedAcknowledgements(t *testing.T) {
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
				Code: "CVE-1", // still relevant
			},

			{
				Code: "CVE-3", // not in report (outdated)
			},
		},
	}

	markOutdatedAcknowledgements(&report, config)

	assert.Equal(t, []string{"CVE-3"}, report.OutdatedAcks)
}

func TestGetProjectList_IgnoresProject(t *testing.T) {
	mockClient := &mockClient{}
	mockClient.On("GetProjectList", []string{"group/to/scan"}).Return([]repository.Project{{Path: "path/of/project", Repository: repository.Gitlab}}, nil)

	mockRepoService := &mockRepoService{}
	mockRepoService.On("Provide", repository.Gitlab).Return(mockClient)

	svc := New(mockRepoService, nil, nil)

	// The ignored list contains the project path, so it should be filtered out
	projects, warn := svc.(*sheriffService).getProjectList(
		[]config.ProjectLocation{{Type: repository.Gitlab, Path: "group/to/scan"}},
		[]config.ProjectLocation{{Type: repository.Gitlab, Path: "path/of/project"}},
	)
	assert.Nil(t, warn)
	assert.Empty(t, projects)
	mockClient.AssertNotCalled(t, "GetProjectList", []string{"path/of/project"})
}

type mockRepoService struct {
	mock.Mock
}

func (c *mockRepoService) Provide(platform repository.RepositoryType) repository.IRepositoryService {
	args := c.Called(platform)
	return args.Get(0).(repository.IRepositoryService)
}

type mockClient struct {
	mock.Mock
}

func (c *mockClient) GetProjectList(paths []string) ([]repository.Project, error) {
	args := c.Called(paths)
	return args.Get(0).([]repository.Project), args.Error(1)
}

func (c *mockClient) CloseVulnerabilityIssue(project repository.Project) error {
	args := c.Called(project)
	return args.Error(0)
}

func (c *mockClient) OpenVulnerabilityIssue(project repository.Project, report string) (*repository.Issue, error) {
	args := c.Called(project, report)
	return args.Get(0).(*repository.Issue), args.Error(1)
}

func (c *mockClient) Clone(project repository.Project, dir string) error {
	args := c.Called(project.RepoUrl, dir)
	return args.Error(0)
}

type mockSlackService struct {
	mock.Mock
}

func (c *mockSlackService) PostMessage(channelName string, options ...slack.MsgOption) (string, error) {
	args := c.Called(channelName, options)
	return args.String(0), args.Error(1)
}

type mockOSVService struct {
	mock.Mock
}

func (c *mockOSVService) Scan(dir string) (*scanner.OsvReport, error) {
	args := c.Called(dir)
	return args.Get(0).(*scanner.OsvReport), args.Error(1)
}

func (c *mockOSVService) GenerateReport(p repository.Project, r *scanner.OsvReport) scanner.Report {
	args := c.Called(p, r)
	return args.Get(0).(scanner.Report)
}

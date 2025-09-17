package publish

import (
	"sheriff/internal/config"
	"sheriff/internal/repository"
	"sheriff/internal/scanner"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Severities are grouped by severity score kind
// and they are displayed as a markdown table
func TestFormatGitlabIssue(t *testing.T) {
	mockVulnerabilities := []scanner.Vulnerability{
		{
			Id:                "test1",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "10.00",
			SeverityScoreKind: scanner.Critical,
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test2",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "0.00",
			SeverityScoreKind: scanner.Low,
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test4",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "0.00",
			SeverityScoreKind: scanner.Acknowledged,
			Summary:           "test",
			Details:           "test",
			AckReason:         "This only happens in Windows, and imagine running serious software in Windows!",
		},
		{
			Id:                "test3",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "5.00",
			SeverityScoreKind: scanner.Moderate,
			Summary:           "test",
			Details:           "test",
		},
	}

	got := formatIssue(scanner.Report{
		Vulnerabilities: mockVulnerabilities,
	})

	want := `
## Severity: CRITICAL
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test1 | 10.00 | ecosystem | name | version | ❌ | test |

## Severity: MODERATE
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test3 | 5.00 | ecosystem | name | version | ❌ | test |

## Severity: LOW
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test2 | 0.00 | ecosystem | name | version | ❌ | test |

## Severity: ACKNOWLEDGED

💡 These vulnerabilities have been acknowledged by the team and are not considered a risk.

| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Reason | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test4 | 0.00 | ecosystem | name | version | ❌ | This only happens in Windows, and imagine running serious software in Windows! | test |
`

	assert.NotEmpty(t, got)
	assert.Contains(t, got, want)
}

// Within a severity kind, vulnerabilities should be sorted by severity score in descending order
func TestFormatGitlabIssueSortWithinGroup(t *testing.T) {
	mockVulnerabilities := []scanner.Vulnerability{
		{
			Id:                "test1",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "8.00",
			SeverityScoreKind: scanner.High, // This has no effect on this test
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test2",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "8.9",
			SeverityScoreKind: scanner.High, // This has no effect on this test
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test3",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "8.5",
			SeverityScoreKind: scanner.High, // This has no effect on this test
			Summary:           "test",
			Details:           "test",
		},
	}

	got := formatIssue(scanner.Report{
		Vulnerabilities: mockVulnerabilities,
	})

	want := `
## Severity: HIGH
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test2 | 8.9 | ecosystem | name | version | ❌ | test |
| https://osv.dev/test3 | 8.5 | ecosystem | name | version | ❌ | test |
| https://osv.dev/test1 | 8.00 | ecosystem | name | version | ❌ | test |
`
	assert.NotEmpty(t, got)
	assert.Contains(t, got, want)
}

func TestMarkdownBoolean(t *testing.T) {
	testCases := map[bool]string{
		true:  "✅",
		false: "❌",
	}

	for input, want := range testCases {
		t.Run(want, func(t *testing.T) {
			got := markdownBoolean(input)
			assert.Equal(t, want, got)
		})
	}
}

func TestPublishAsGitlabIssues(t *testing.T) {
	mockGitlabService := &mockGitlabService{}
	mockGitlabService.On("OpenVulnerabilityIssue", mock.Anything, mock.Anything).Return(&repository.Issue{WebURL: "https://my-issue.com"}, nil)

	mockRepoService := &mockRepoService{}
	mockRepoService.On("Provide", repository.Gitlab).Return(mockGitlabService)

	reports := []scanner.Report{
		{
			Project:      repository.Project{Repository: repository.Gitlab},
			IsVulnerable: true,
			Vulnerabilities: []scanner.Vulnerability{
				{
					Id: "test1",
				},
			},
		},
	}

	_ = PublishAsIssues(reports, mockRepoService)
	mockGitlabService.AssertExpectations(t)
	mockRepoService.AssertExpectations(t)

	t.Run("FillsTheIssueUrl", func(t *testing.T) {
		assert.Equal(t, "https://my-issue.com", reports[0].IssueUrl)
	})

}

func TestGitlabIssueReportHeader(t *testing.T) {
	origNow := now
	now = func() time.Time {
		return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	defer func() {
		now = origNow
	}()

	got := getVulnReportHeader()

	want := `ℹ️ This issue lists all the vulnerabilities found in the project by [Sheriff](https://github.com/elementsinteractive/sheriff) on 2021-01-01.`

	assert.Contains(t, got, want)

}

type mockRepoService struct {
	mock.Mock
}

func (c *mockRepoService) GetProjectList(paths []config.ProjectLocation) ([]repository.Project, error) {
	args := c.Called(paths)
	return args.Get(0).([]repository.Project), args.Error(1)
}

func (c *mockRepoService) Provide(platform repository.RepositoryType) repository.IRepositoryService {
	args := c.Called(platform)
	return args.Get(0).(repository.IRepositoryService)
}

type mockGitlabService struct {
	mock.Mock
}

func (c *mockGitlabService) GetProjectList(paths []string) ([]repository.Project, error) {
	args := c.Called(paths)
	return args.Get(0).([]repository.Project), args.Error(1)
}

func (c *mockGitlabService) CloseVulnerabilityIssue(project repository.Project) error {
	args := c.Called(project)
	return args.Error(0)
}

func (c *mockGitlabService) OpenVulnerabilityIssue(project repository.Project, report string) (*repository.Issue, error) {
	args := c.Called(project, report)
	return args.Get(0).(*repository.Issue), args.Error(1)
}

func (c *mockGitlabService) Clone(project repository.Project, dir string) error {
	args := c.Called(project.RepoUrl, dir)
	return args.Error(0)
}

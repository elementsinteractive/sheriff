package repository

const VulnerabilityIssueTitle = "Sheriff - 🚨 Vulnerability report"

type RepositoryType string

const (
	Gitlab RepositoryType = "gitlab"
	Github RepositoryType = "github"
)

type Project struct {
	ID         int
	Name       string
	Slug       string
	Path       string
	WebURL     string
	RepoUrl    string
	Repository RepositoryType
}

type Issue struct {
	ID     int
	Title  string
	WebURL string
	Open   bool
}

type IRepositoryService interface {
	GetProjectList(paths []string) (projects []Project, warn error)
	CloseVulnerabilityIssue(project Project) error
	OpenVulnerabilityIssue(project Project, report string) (*Issue, error)
	Clone(url string, dir string) error
}

package gitlab

import (
	"errors"
	"os"
	"path/filepath"
	"sheriff/internal/repository"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestNewService(t *testing.T) {
	s, err := New("token")

	assert.Nil(t, err)
	assert.NotNil(t, s)
}

func TestGetProjectListWithTopLevelGroup(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListGroupProjects", "group", mock.Anything, mock.Anything).Return([]*gitlab.Project{{Name: "Hello World"}}, &gitlab.Response{}, nil)

	svc := gitlabService{client: &mockClient}

	projects, err := svc.GetProjectList([]string{"group"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockClient.AssertExpectations(t)
}

func TestGetProjectListWithSubGroup(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListGroupProjects", "group/subgroup", mock.Anything, mock.Anything).Return([]*gitlab.Project{{Name: "Hello World"}}, &gitlab.Response{}, nil)

	svc := gitlabService{client: &mockClient}

	projects, err := svc.GetProjectList([]string{"group/subgroup"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockClient.AssertExpectations(t)
}

func TestGetProjectListWithProjects(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListGroupProjects", "group/subgroup/project", mock.Anything, mock.Anything).Return([]*gitlab.Project{}, &gitlab.Response{}, errors.New("no group"))
	mockClient.On("GetProject", "group/subgroup/project", mock.Anything, mock.Anything).Return(&gitlab.Project{Name: "Hello World", PathWithNamespace: "group/subgroup/project"}, &gitlab.Response{}, nil)

	svc := gitlabService{client: &mockClient}

	projects, err := svc.GetProjectList([]string{"group/subgroup/project"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockClient.AssertExpectations(t)
}

func TestGetProjectListWithGroupAndProjects(t *testing.T) {
	project1 := &gitlab.Project{ID: 1, PathWithNamespace: "group/subgroup/project"}
	project2 := &gitlab.Project{ID: 2, PathWithNamespace: "group/project"}

	mockClient := mockClient{}
	mockClient.On("ListGroupProjects", "group", mock.Anything, mock.Anything).Return([]*gitlab.Project{project1, project2}, &gitlab.Response{}, nil)
	mockClient.On("ListGroupProjects", "group/subgroup", mock.Anything, mock.Anything).Return([]*gitlab.Project{project1}, &gitlab.Response{}, nil)
	mockClient.On("ListGroupProjects", project1.PathWithNamespace, mock.Anything, mock.Anything).Return([]*gitlab.Project{}, &gitlab.Response{}, errors.New("no group"))
	mockClient.On("GetProject", project1.PathWithNamespace, mock.Anything, mock.Anything).Return(project1, &gitlab.Response{}, nil)

	svc := gitlabService{client: &mockClient}

	projects, err := svc.GetProjectList([]string{"group", "group/subgroup", project1.PathWithNamespace})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Len(t, projects, 2)
	assert.Equal(t, project1.ID, projects[0].ID)
	assert.Equal(t, project2.ID, projects[1].ID)
	mockClient.AssertExpectations(t)
}

func TestGetProjectListWithNextPage(t *testing.T) {
	project1 := &gitlab.Project{ID: 1}
	project2 := &gitlab.Project{ID: 2}

	mockClient := mockClient{}
	mockClient.On("ListGroupProjects", "group/subgroup", &gitlab.ListGroupProjectsOptions{
		Archived:         gitlab.Ptr(false),
		Simple:           gitlab.Ptr(true),
		IncludeSubGroups: gitlab.Ptr(true),
		WithShared:       gitlab.Ptr(false),
		ListOptions: gitlab.ListOptions{
			Page: 1,
		},
	}, mock.Anything).Return([]*gitlab.Project{project1}, &gitlab.Response{NextPage: 2, TotalPages: 2}, nil)
	mockClient.On("ListGroupProjects", "group/subgroup", &gitlab.ListGroupProjectsOptions{
		Archived:         gitlab.Ptr(false),
		Simple:           gitlab.Ptr(true),
		IncludeSubGroups: gitlab.Ptr(true),
		WithShared:       gitlab.Ptr(false),
		ListOptions: gitlab.ListOptions{
			Page: 2,
		},
	}, mock.Anything).Return([]*gitlab.Project{project2}, &gitlab.Response{NextPage: 0, TotalPages: 2}, nil)

	svc := gitlabService{client: &mockClient}

	projects, err := svc.GetProjectList([]string{"group/subgroup"})

	assert.Nil(t, err)
	assert.Len(t, projects, 2)
	assert.Equal(t, project1.ID, projects[0].ID)
	assert.Equal(t, project2.ID, projects[1].ID)
	mockClient.AssertExpectations(t)
}

func TestCloseVulnerabilityIssue(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{{IID: 2, State: "opened"}}, nil, nil)
	mockClient.On("UpdateIssue", 1, 2, mock.Anything, mock.Anything).Return(&gitlab.Issue{State: "closed"}, nil, nil)

	svc := gitlabService{client: &mockClient}

	err := svc.CloseVulnerabilityIssue(repository.Project{ID: 1})

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

func TestCloseVulnerabilityIssueAlreadyClosed(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{{State: "closed"}}, nil, nil)

	svc := gitlabService{client: &mockClient}

	err := svc.CloseVulnerabilityIssue(repository.Project{})

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

func TestCloseVulnerabilityIssueNoIssue(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{}, nil, nil)

	svc := gitlabService{client: &mockClient}

	err := svc.CloseVulnerabilityIssue(repository.Project{})

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

func TestOpenVulnerabilityIssue(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{}, nil, nil)
	mockClient.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything).Return(&gitlab.Issue{Title: "666"}, nil, nil)

	svc := gitlabService{client: &mockClient}

	i, err := svc.OpenVulnerabilityIssue(repository.Project{}, "report")
	assert.Nil(t, err)
	assert.NotNil(t, i)
	assert.Equal(t, "666", i.Title)
}

func TestFilterUniqueProjects(t *testing.T) {
	projects := []repository.Project{
		{ID: 1},
		{ID: 1},
		{ID: 2},
		{ID: 3},
		{ID: 1},
	}

	uniqueProjects := filterUniqueProjects(projects)

	assert.Len(t, uniqueProjects, 3)
	assert.Equal(t, 1, uniqueProjects[0].ID)
	assert.Equal(t, 2, uniqueProjects[1].ID)
	assert.Equal(t, 3, uniqueProjects[2].ID)
}

func TestDereferenceProjectsPointers(t *testing.T) {
	projects := []*gitlab.Project{
		{ID: 1},
		nil,
		{ID: 2},
		nil,
	}

	dereferencedProjects, errCount := dereferenceProjectsPointers(projects)

	assert.Len(t, dereferencedProjects, 2)
	assert.Equal(t, 1, dereferencedProjects[0].ID)
	assert.Equal(t, 2, dereferencedProjects[1].ID)
	assert.Equal(t, 2, errCount)
}
func TestDownloadRepository(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "sheriff-clone-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	stubArchive, err := os.ReadFile("../testdata/sample-archive.tar.gz")
	require.NoError(t, err)

	mockClient := mockClient{}
	mockClient.On("Archive", 123, mock.Anything, mock.Anything).Return(stubArchive, &gitlab.Response{}, nil)

	svc := gitlabService{client: &mockClient}

	// Create a test project
	testProject := repository.Project{
		ID:   123,
		Name: "test-project",
		Path: "group/project",
	}

	err = svc.DownloadRepository(testProject, tempDir)

	// Verify no errors
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)

	// Verify files were extracted correctly
	readmeContent, err := os.ReadFile(filepath.Join(tempDir, "README.md"))
	assert.NoError(t, err)
	assert.Equal(t, "# Test Project\n\nThis is a test project for testing GitLab archive extraction.", string(readmeContent))

	srcContent, err := os.ReadFile(filepath.Join(tempDir, "src", "main.go"))
	assert.NoError(t, err)
	assert.Equal(t, "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"Hello from test project!\")\n}", string(srcContent))

	// Verify directory structure
	_, err = os.Stat(filepath.Join(tempDir, "src"))
	assert.NoError(t, err, "src directory should exist")
}

type mockClient struct {
	mock.Mock
}

func (c *mockClient) GetProject(pid interface{}, opt *gitlab.GetProjectOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Project, *gitlab.Response, error) {
	args := c.Called(pid, opt, options)
	var r *gitlab.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*gitlab.Response)
	}
	return args.Get(0).(*gitlab.Project), r, args.Error(2)
}

func (c *mockClient) ListGroupProjects(gid interface{}, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error) {
	args := c.Called(gid, opt, options)
	var r *gitlab.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*gitlab.Response)
	}
	return args.Get(0).([]*gitlab.Project), r, args.Error(2)
}

func (c *mockClient) ListProjectIssues(projectId interface{}, opt *gitlab.ListProjectIssuesOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Issue, *gitlab.Response, error) {
	args := c.Called(projectId, opt, options)
	var r *gitlab.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*gitlab.Response)
	}
	return args.Get(0).([]*gitlab.Issue), r, args.Error(2)
}

func (c *mockClient) CreateIssue(projectId interface{}, opt *gitlab.CreateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	args := c.Called(projectId, opt, options)
	var r *gitlab.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*gitlab.Response)
	}
	return args.Get(0).(*gitlab.Issue), r, args.Error(2)
}

func (c *mockClient) UpdateIssue(projectId interface{}, issueId int, opt *gitlab.UpdateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	args := c.Called(projectId, issueId, opt, options)
	var r *gitlab.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*gitlab.Response)
	}
	return args.Get(0).(*gitlab.Issue), r, args.Error(2)
}

func (c *mockClient) Archive(pid interface{}, opt *gitlab.ArchiveOptions, options ...gitlab.RequestOptionFunc) ([]byte, *gitlab.Response, error) {
	args := c.Called(pid, opt, options)
	var r *gitlab.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*gitlab.Response)
	}
	return args.Get(0).([]byte), r, args.Error(2)
}

package github

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sheriff/internal/repository"
	"testing"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetProjectListOrganizationRepos(t *testing.T) {
	mockService := mockService{}
	mockService.On("GetOrganizationRepositories", "org", mock.Anything).Return([]*github.Repository{{Name: github.Ptr("Hello World")}}, &github.Response{}, nil)

	svc := githubService{
		client: &mockService,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	projects, err := svc.GetProjectList([]string{"org"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockService.AssertExpectations(t)
}

func TestGetProjectListUserRepos(t *testing.T) {
	mockService := mockService{}
	mockService.On("GetOrganizationRepositories", "user", mock.Anything).Return([]*github.Repository{}, &github.Response{}, errors.New("error"))
	mockService.On("GetUserRepositories", "user", mock.Anything).Return([]*github.Repository{{Name: github.Ptr("Hello World")}}, &github.Response{}, nil)

	svc := githubService{
		client: &mockService,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	projects, err := svc.GetProjectList([]string{"user"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockService.AssertExpectations(t)
}

func TestGetProjectSpecificRepo(t *testing.T) {
	mockService := mockService{}
	mockService.On("GetRepository", "owner", "repo").Return(&github.Repository{Name: github.Ptr("Hello World")}, &github.Response{}, nil)

	svc := githubService{
		client: &mockService,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	projects, err := svc.GetProjectList([]string{"owner/repo"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockService.AssertExpectations(t)
}

func TestGetProjectListWithNextPage(t *testing.T) {
	project1 := &github.Repository{ID: github.Ptr(int64(1))}
	project2 := &github.Repository{ID: github.Ptr(int64(2))}

	mockService := mockService{}
	mockService.On("GetOrganizationRepositories", "org", &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
	}, mock.Anything).Return([]*github.Repository{project1}, &github.Response{NextPage: 2}, nil)
	mockService.On("GetOrganizationRepositories", "org", &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page:    2,
			PerPage: 100,
		},
	}, mock.Anything).Return([]*github.Repository{project2}, &github.Response{NextPage: 0}, nil)

	svc := githubService{
		client: &mockService,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	projects, err := svc.GetProjectList([]string{"org"})

	assert.Nil(t, err)
	assert.Len(t, projects, 2)
	assert.Equal(t, int(*project1.ID), projects[0].ID)
	assert.Equal(t, int(*project2.ID), projects[1].ID)
	mockService.AssertExpectations(t)
}

type mockService struct {
	mock.Mock
}

func (c *mockService) GetRepository(owner string, repo string) (*github.Repository, *github.Response, error) {
	args := c.Called(owner, repo)
	var r *github.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*github.Response)
	}
	return args.Get(0).(*github.Repository), r, args.Error(2)
}

func (c *mockService) GetOrganizationRepositories(org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error) {
	args := c.Called(org, opts)
	var r *github.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*github.Response)
	}
	return args.Get(0).([]*github.Repository), r, args.Error(2)
}

func (c *mockService) GetUserRepositories(user string, opts *github.RepositoryListByUserOptions) ([]*github.Repository, *github.Response, error) {
	args := c.Called(user, opts)
	var r *github.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*github.Response)
	}
	return args.Get(0).([]*github.Repository), r, args.Error(2)
}

func (c *mockService) GetArchiveLink(owner string, repo string, archiveFormat github.ArchiveFormat, opts *github.RepositoryContentGetOptions) (*url.URL, *github.Response, error) {
	args := c.Called(owner, repo, archiveFormat, opts)
	var r *github.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*github.Response)
	}
	return args.Get(0).(*url.URL), r, args.Error(2)
}

func TestDownloadRepository(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "sheriff-clone-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Read the same stub archive used by GitLab tests
	stubArchive, err := os.ReadFile("../testdata/sample-archive.tar.gz")
	require.NoError(t, err)

	// Create a mock HTTP server to serve the archive
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(stubArchive); err != nil {
			http.Error(w, "Failed to write archive", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	// Parse the server URL
	archiveURL, err := url.Parse(server.URL + "/archive.tar.gz")
	require.NoError(t, err)

	// Setup mock client
	mockService := mockService{}
	mockService.On("GetArchiveLink", "owner", "repo", github.Tarball, mock.Anything).Return(archiveURL, &github.Response{}, nil)

	svc := githubService{
		client: &mockService,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Create a test project
	testProject := repository.Project{
		ID:   123,
		Name: "test-project",
		Path: "owner/repo",
	}

	err = svc.DownloadRepository(testProject, tempDir)

	// Verify no errors
	assert.NoError(t, err)
	mockService.AssertExpectations(t)

	// Verify files were extracted correctly (same verification as GitLab test)
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

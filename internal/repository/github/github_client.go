// Package github provides a GitHub service to interact with the GitHub API.
package github

import (
	"context"
	"net/url"
	"time"

	"github.com/google/go-github/v68/github"
)

const defaultTimeout = 30 * time.Second

// This client is a thin wrapper around the go-github library. It provides an interface to the GitHub client
// The main purpose of this client is to provide an interface to the GitHub client which can be mocked in tests.
// As such this MUST be as thin as possible and MUST not contain any business logic, since it is not testable.
type iGithubClient interface {
	GetRepository(owner string, repo string) (*github.Repository, *github.Response, error)
	GetOrganizationRepositories(org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error)
	GetUserRepositories(user string, opts *github.RepositoryListByUserOptions) ([]*github.Repository, *github.Response, error)
	GetArchiveLink(owner string, repo string, archiveFormat github.ArchiveFormat, opts *github.RepositoryContentGetOptions) (*url.URL, *github.Response, error)
	ListRepositoryIssues(owner string, repo string, opts *github.IssueListByRepoOptions) ([]*github.Issue, *github.Response, error)
	CreateIssue(owner string, repo string, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
	UpdateIssue(owner string, repo string, number int, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
}

type githubClient struct {
	client *github.Client
}

func (c *githubClient) ListRepositoryIssues(owner, repo string, opts *github.IssueListByRepoOptions) ([]*github.Issue, *github.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.client.Issues.ListByRepo(ctx, owner, repo, opts)
}

func (c *githubClient) CreateIssue(owner, repo string, issue *github.IssueRequest) (*github.Issue, *github.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.client.Issues.Create(ctx, owner, repo, issue)
}

func (c *githubClient) UpdateIssue(owner, repo string, number int, issue *github.IssueRequest) (*github.Issue, *github.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.client.Issues.Edit(ctx, owner, repo, number, issue)
}
func (c *githubClient) GetRepository(owner string, repo string) (*github.Repository, *github.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.client.Repositories.Get(ctx, owner, repo)
}

func (c *githubClient) GetOrganizationRepositories(org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.client.Repositories.ListByOrg(ctx, org, opts)
}

func (c *githubClient) GetUserRepositories(user string, opts *github.RepositoryListByUserOptions) ([]*github.Repository, *github.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.client.Repositories.ListByUser(ctx, user, opts)
}

func (c *githubClient) GetArchiveLink(owner string, repo string, archiveFormat github.ArchiveFormat, opts *github.RepositoryContentGetOptions) (*url.URL, *github.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return c.client.Repositories.GetArchiveLink(ctx, owner, repo, archiveFormat, opts, 3)
}

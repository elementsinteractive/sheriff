package github

import (
	"context"
	"errors"
	"fmt"

	"net/http"
	"sheriff/internal/compress"
	"sheriff/internal/repository"
	"strings"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/google/go-github/v68/github"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

type githubService struct {
	client     iGithubClient
	httpClient *http.Client
	token      string
}

// newGithubRepo creates a new GitHub repository service
func New(token string) githubService {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	client := github.NewClient(tc)
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	s := githubService{
		client:     &githubClient{client: client},
		httpClient: httpClient,
		token:      token,
	}

	return s
}

func (s githubService) GetProjectList(paths []string) (projects []repository.Project, warn error) {
	g := new(errgroup.Group)
	reposChan := make(chan []github.Repository, len(paths))
	for _, path := range paths {
		g.Go(func() error {
			repos, err := s.getPathRepos(path)
			reposChan <- repos
			if err != nil {
				return err
			}

			return nil
		})
	}
	warn = g.Wait()

	close(reposChan)

	// Collect repos
	var allRepos []github.Repository
	for repos := range reposChan {
		allRepos = append(allRepos, repos...)
	}

	projects = pie.Map(allRepos, mapGithubProject)

	return
}

// CloseVulnerabilityIssue closes the vulnerability issue for the given project
func (s githubService) CloseVulnerabilityIssue(project repository.Project) (err error) {
	issue, err := s.getVulnerabilityIssue(project.GroupOrOwner, project.Name)
	if err != nil {
		return fmt.Errorf("failed to fetch current list of issues: %w", err)
	}
	if issue == nil {
		log.Info().Str("project", project.Path).Msg("No issue to close, nothing to do")
		return nil
	}
	if issue.GetState() == "closed" {
		log.Info().Str("project", project.Path).Msg("Issue already closed")
		return nil
	}
	state := "closed"
	_, _, err = s.client.UpdateIssue(project.GroupOrOwner, project.GroupOrOwner, issue.GetNumber(), &github.IssueRequest{
		State: &state,
	})
	if err != nil {
		return fmt.Errorf("failed to update issue: %w", err)
	}
	log.Info().Str("project", project.Path).Msg("Issue closed")
	return nil
}

// OpenVulnerabilityIssue opens or updates the vulnerability issue for the given project
func (s githubService) OpenVulnerabilityIssue(project repository.Project, report string) (issue *repository.Issue, err error) {
	vulnTitle := repository.VulnerabilityIssueTitle
	ghIssue, err := s.getVulnerabilityIssue(project.GroupOrOwner, project.Name)
	if err != nil {
		return nil, fmt.Errorf("[%v] Failed to fetch current list of issues: %w", project.Path, err)
	}
	if ghIssue == nil {
		log.Info().Str("project", project.Path).Msg("Creating new issue")
		newIssue := &github.IssueRequest{
			Title: &vulnTitle,
			Body:  &report,
		}
		created, _, err := s.client.CreateIssue(project.GroupOrOwner, project.Name, newIssue)
		if err != nil {
			return nil, fmt.Errorf("[%v] failed to create new issue: %w", project.Path, err)
		}
		return mapGithubIssuePtr(created), nil
	}
	log.Info().Str("project", project.Path).Int("issue", ghIssue.GetNumber()).Msg("Updating existing issue")
	state := "open"
	updatedIssue := &github.IssueRequest{
		Body:  &report,
		State: &state,
	}
	edited, _, err := s.client.UpdateIssue(project.GroupOrOwner, project.Name, ghIssue.GetNumber(), updatedIssue)
	if err != nil {
		return nil, fmt.Errorf("[%v] Failed to update issue: %w", project.Path, err)
	}
	if edited.GetState() != "open" {
		return nil, errors.New("failed to reopen issue")
	}
	return mapGithubIssuePtr(edited), nil
}

// getVulnerabilityIssue returns the vulnerability issue for the given repo (by title)
func (s githubService) getVulnerabilityIssue(owner, repo string) (*github.Issue, error) {
	opts := &github.IssueListByRepoOptions{
		State:       "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	vulnTitle := repository.VulnerabilityIssueTitle
	for {
		issues, resp, err := s.client.ListRepositoryIssues(owner, repo, opts)
		if err != nil {
			return nil, err
		}
		for _, issue := range issues {
			if issue != nil && issue.GetTitle() == vulnTitle {
				return issue, nil
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil, nil
}
func mapGithubIssue(i github.Issue) repository.Issue {
	return repository.Issue{
		Title:  i.GetTitle(),
		WebURL: i.GetHTMLURL(),
	}
}

func mapGithubIssuePtr(i *github.Issue) *repository.Issue {
	if i == nil {
		return nil
	}
	issue := mapGithubIssue(*i)
	return &issue
}

func (s githubService) Download(project repository.Project, dir string) (err error) {
	// Get archive download URL using GitHub API
	archiveURL, _, err := s.client.GetArchiveLink(project.GroupOrOwner, project.Name, github.Tarball, &github.RepositoryContentGetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get GitHub archive link: %w", err)
	}

	log.Debug().Str("archiveURL", archiveURL.String()).Msg("Got GitHub archive URL")

	// Create request with context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", archiveURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Download the archive from the URL using the shared HTTP client
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download GitHub archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download GitHub archive, status: %s", resp.Status)
	}

	return compress.ExtractTarGz(resp.Body, dir)
}

func (s githubService) getPathRepos(path string) (repositories []github.Repository, err error) {
	parts := strings.Split(path, "/")

	if len(parts) == 1 {
		return s.getOwnerRepos(parts[0])
	} else if len(parts) == 2 {
		repo, err := s.getOwnerRepository(parts[0], parts[1])
		if err != nil {
			return nil, errors.Join(fmt.Errorf("failed to get repository %s", path), err)
		} else if repo == nil {
			return nil, errors.New("repository unexpectedly nil")
		}

		return []github.Repository{*repo}, err
	} else {
		return nil, fmt.Errorf("project %v path of unexpected length %v", path, len(parts))
	}
}

func (s githubService) getOwnerRepos(owner string) (repos []github.Repository, err error) {
	// Try first as `organization`
	repoPtrs, err := s.getOrganizationRepos(owner)
	if err != nil {
		// Try again as `user`
		repoPtrs, err = s.getUserRepos(owner)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("could not fetch repos for owner %v", owner), err)
		}
	}

	repos = derefRepoPtrs(owner, repoPtrs)

	return
}

func (s githubService) getOrganizationRepos(org string) (repos []*github.Repository, err error) {
	repos, err = getGithubPaginatedResults(func(listOpts github.ListOptions) ([]*github.Repository, *github.Response, error) {
		opts := &github.RepositoryListByOrgOptions{
			ListOptions: listOpts,
		}
		return s.client.GetOrganizationRepositories(org, opts)
	})

	return
}

func (s githubService) getUserRepos(user string) (repos []*github.Repository, err error) {
	repos, err = getGithubPaginatedResults(func(listOpts github.ListOptions) ([]*github.Repository, *github.Response, error) {
		opts := &github.RepositoryListByUserOptions{
			Type:        "owner",
			ListOptions: listOpts,
		}
		return s.client.GetUserRepositories(user, opts)
	})

	return
}

func getGithubPaginatedResults[T interface{}](paginatedFunc func(github.ListOptions) ([]T, *github.Response, error)) (results []T, err error) {
	opts := github.ListOptions{
		PerPage: 100,
		Page:    1,
	}
	for {
		pageResults, resp, err := paginatedFunc(opts)
		if err != nil {
			return nil, err
		}

		results = append(results, pageResults...)
		if resp.NextPage == 0 {
			break
		}

		opts.Page = resp.NextPage
	}

	return
}

func (s *githubService) getOwnerRepository(owner string, name string) (repo *github.Repository, err error) {
	repo, _, err = s.client.GetRepository(owner, name)
	if err != nil {
		return nil, err
	}

	return
}

func derefRepoPtrs(owner string, repoPtrs []*github.Repository) (repos []github.Repository) {
	var errCount = 0
	for _, repo := range repoPtrs {
		if repo == nil {
			errCount++
			continue
		}
		repos = append(repos, *repo)
	}

	if errCount > 0 {
		log.Warn().Str("owner", owner).Int("count", errCount).Msg("Found nil repositories, skipping them.")
	}

	return
}

func mapGithubProject(r github.Repository) repository.Project {
	var groupName = ""
	owner := r.GetOwner()
	if owner != nil {
		groupName = owner.GetLogin()
	}

	return repository.Project{
		ID:           int(valueOrEmpty(r.ID)),
		Name:         valueOrEmpty(r.Name),
		GroupOrOwner: valueOrEmpty(&groupName),
		Path:         valueOrEmpty(r.FullName),
		Slug:         valueOrEmpty(r.Name),
		WebURL:       valueOrEmpty(r.HTMLURL),
		RepoUrl:      valueOrEmpty(r.HTMLURL),
		Repository:   repository.Github,
	}
}

func valueOrEmpty[T interface{}](val *T) (r T) {
	if val != nil {
		return *val
	}

	return r
}

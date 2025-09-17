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
	"golang.org/x/sync/errgroup"
)

type githubService struct {
	client     iGithubClient
	httpClient *http.Client
	token      string
}

// newGithubRepo creates a new GitHub repository service
func New(token string) githubService {
	client := github.NewClient(nil)
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
	return errors.New("CloseVulnerabilityIssue not yet implemented") // TODO #9 Add github support
}

// OpenVulnerabilityIssue opens or updates the vulnerability issue for the given project
func (s githubService) OpenVulnerabilityIssue(project repository.Project, report string) (issue *repository.Issue, err error) {
	return nil, errors.New("OpenVulnerabilityIssue not yet implemented") // TODO #9 Add github support
}

func (s githubService) DownloadRepository(project repository.Project, dir string) (err error) {
	// Extract owner and repo from project path (format: "owner/repo")
	owner, repo, err := s.extractOwnerRepo(project.Path)
	if err != nil {
		return fmt.Errorf("failed to extract owner/repo from path %s: %w", project.Path, err)
	}

	log.Debug().Str("owner", owner).Str("repo", repo).Str("dir", dir).Msg("Downloading GitHub archive")

	// Get archive download URL using GitHub API
	archiveURL, _, err := s.client.GetArchiveLink(owner, repo, github.Tarball, &github.RepositoryContentGetOptions{})
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
	return repository.Project{
		ID:         int(valueOrEmpty(r.ID)),
		Name:       valueOrEmpty(r.Name),
		Path:       valueOrEmpty(r.FullName),
		Slug:       valueOrEmpty(r.Name),
		WebURL:     valueOrEmpty(r.HTMLURL),
		RepoUrl:    valueOrEmpty(r.HTMLURL),
		Repository: repository.Github,
	}
}

func valueOrEmpty[T interface{}](val *T) (r T) {
	if val != nil {
		return *val
	}

	return r
}

// extractOwnerRepo extracts owner and repo name from GitHub project path
func (s githubService) extractOwnerRepo(path string) (owner, repo string, err error) {
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid GitHub project path format, expected 'owner/repo', got: %s", path)
	}
	return parts[0], parts[1], nil
}

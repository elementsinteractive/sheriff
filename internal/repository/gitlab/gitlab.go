package gitlab

import (
	"errors"
	"fmt"
	"sheriff/internal/repository"
	"sync"

	"github.com/elliotchance/pie/v2"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/rs/zerolog/log"
	"github.com/xanzy/go-gitlab"
)

type gitlabService struct {
	client iclient
	token  string
}

// newGitlabRepo creates a new GitLab repository service
func New(token string) (*gitlabService, error) {
	c, err := gitlab.NewClient(token)
	if err != nil {
		return nil, err
	}

	s := gitlabService{client: &client{client: c}, token: token}

	return &s, nil
}

func (s gitlabService) GetProjectList(paths []string) (projects []repository.Project, warn error) {
	projects, pwarn := s.gatherProjectsFromGroupsOrProjects(paths)
	if pwarn != nil {
		pwarn = errors.Join(errors.New("errors occured when gathering projects"), pwarn)
		warn = errors.Join(pwarn, warn)
	}

	projectsNamespaces := pie.Map(projects, func(p repository.Project) string { return p.Path })
	log.Info().Strs("projects", projectsNamespaces).Msg("Projects to scan")

	return projects, warn
}

// CloseVulnerabilityIssue closes the vulnerability issue for the given project
func (s gitlabService) CloseVulnerabilityIssue(project repository.Project) (err error) {
	issue, err := s.getVulnerabilityIssue(project)
	if err != nil {
		return errors.Join(errors.New("failed to fetch current list of issues"), err)
	}

	if issue == nil {
		log.Info().Str("project", project.Path).Msg("No issue to close, nothing to do")
		return
	}

	if issue.State == "closed" {
		log.Info().Str("project", project.Path).Msg("Issue already closed")
		return
	}

	issue, _, err = s.client.UpdateIssue(project.ID, issue.ID, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
	})
	if err != nil {
		return errors.Join(errors.New("failed to update issue"), err)
	}

	if issue.State != "closed" {
		return errors.New("failed to close issue")
	}

	log.Info().Str("project", project.Path).Msg("Issue closed")

	return
}

// OpenVulnerabilityIssue opens or updates the vulnerability issue for the given project
func (s gitlabService) OpenVulnerabilityIssue(project repository.Project, report string) (issue *repository.Issue, err error) {
	gitlabIssue, err := s.getVulnerabilityIssue(project)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("[%v] Failed to fetch current list of issues", project.Path), err)
	}

	if gitlabIssue == nil {
		log.Info().Str("project", project.Path).Msg("Creating new issue")

		gitlabIssue, _, err := s.client.CreateIssue(project.ID, &gitlab.CreateIssueOptions{
			Title:       gitlab.Ptr(repository.VulnerabilityIssueTitle),
			Description: &report,
		})
		if err != nil {
			return nil, errors.Join(fmt.Errorf("[%v] failed to create new issue", project.Path), err)
		}

		return mapIssuePtr(gitlabIssue), nil
	}

	log.Info().Str("project", project.Path).Int("issue", gitlabIssue.IID).Msg("Updating existing issue")

	if updatedIssue, _, err := s.client.UpdateIssue(project.ID, gitlabIssue.IID, &gitlab.UpdateIssueOptions{
		Description: &report,
		StateEvent:  gitlab.Ptr("reopen"),
	}); err != nil {
		return nil, errors.Join(fmt.Errorf("[%v] Failed to update issue", project.Path), err)
	} else {
		if updatedIssue.State != "opened" {
			return nil, errors.New("failed to reopen issue")
		}

		issue = mapIssuePtr(updatedIssue)
	}

	return
}

func (s gitlabService) Clone(url string, dir string) (err error) {
	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL: url,
		Auth: &http.BasicAuth{
			Username: "N/A",
			Password: s.token,
		},
		Depth: 1,
	})

	return err
}

// This function receives a list of paths which can be gitlab projects or groups
// and returns the list of projects within those paths and the list of projects contained within those groups and their subgroups.
func (s gitlabService) gatherProjectsFromGroupsOrProjects(paths []string) (projects []repository.Project, warn error) {
	for _, path := range paths {
		gp, gpwarn, gerr := s.getProjectsFromGroupOrProject(path)
		if gerr != nil {
			log.Error().Err(gerr).Str("group", path).Msg("Failed to fetch group")
			gerr = errors.Join(fmt.Errorf("failed to fetch group %v", path), gerr)
			warn = errors.Join(gerr, warn)
			continue
		}
		if gpwarn != nil {
			warn = errors.Join(gpwarn, warn)
		}

		projects = append(projects, gp...)
	}

	// Filter unique projects -- there may be duplicates between groups, other groups and projects
	projects = filterUniqueProjects(projects)

	return
}

// This function receives a path that could either be a gitlab group, or a gitlab path.
// It first tries to get the path as a group.
//
//	If it succeeds then it returns all projects of that group & its subgroups.
//	If it fails then it tries to get the path as a project.
func (s gitlabService) getProjectsFromGroupOrProject(path string) (projects []repository.Project, warn error, err error) {
	gp, gpwarn, gperr := s.listGroupProjects(path)
	if gperr != nil {
		log.Debug().Str("path", path).Msg("failed to fetch as group. trying as project")
		p, _, perr := s.client.GetProject(path, &gitlab.GetProjectOptions{})
		if perr != nil {
			return nil, errors.Join(fmt.Errorf("failed to get group %v", path), gperr), nil
		} else if p == nil {
			return nil, fmt.Errorf("unexpected nil project %v", path), nil
		}

		return []repository.Project{mapProject(*p)}, nil, nil
	}

	ps := pie.Map(gp, mapProject)

	return ps, gpwarn, nil
}

// getVulnerabilityIssue returns the vulnerability issue for the given project
func (s gitlabService) getVulnerabilityIssue(project repository.Project) (issue *gitlab.Issue, err error) {
	issues, _, err := s.client.ListProjectIssues(project.ID, &gitlab.ListProjectIssuesOptions{
		Search: gitlab.Ptr(repository.VulnerabilityIssueTitle),
		In:     gitlab.Ptr("title"),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch current list of issues")
	}

	if len(issues) > 0 {
		if issues[0] == nil {
			return nil, fmt.Errorf("unexpected nil issue %v", project.Path)
		}

		issue = issues[0]
	}

	return
}

// listGroupProjects returns the list of projects for the given group ID
func (s gitlabService) listGroupProjects(path string) (projects []gitlab.Project, warn error, err error) {
	projectPtrs, response, err := s.client.ListGroupProjects(path,
		&gitlab.ListGroupProjectsOptions{
			Archived:         gitlab.Ptr(false),
			Simple:           gitlab.Ptr(true),
			IncludeSubGroups: gitlab.Ptr(true),
			WithShared:       gitlab.Ptr(false),
			ListOptions: gitlab.ListOptions{
				Page: 1,
			},
		})
	if err != nil {
		return nil, nil, errors.Join(errors.New("failed to fetch list of projects"), err)
	}

	projects, errCount := dereferenceProjectsPointers(projectPtrs)
	if errCount > 0 {
		log.Warn().Str("path", path).Int("count", errCount).Msg("Found nil projects, skipping them.")
	}

	if response.TotalPages > 1 {
		nextProjects, lgwarn := s.listGroupNextProjects(path, response.TotalPages)
		if lgwarn != nil {
			lgwarn = errors.Join(errors.New("errors occured when fetching next pages"), lgwarn)
			warn = errors.Join(lgwarn, warn)
		}

		projects = append(projects, nextProjects...)
	}

	return
}

func ToChan[T any](s []T) <-chan T {
	ch := make(chan T, len(s))
	for _, e := range s {
		ch <- e
	}
	close(ch)
	return ch
}

// listGroupNextProjects returns the list of projects for the given group ID from the next pages
func (s gitlabService) listGroupNextProjects(path string, totalPages int) (projects []gitlab.Project, warn error) {
	var wg sync.WaitGroup
	nextProjectsChan := make(chan []gitlab.Project, totalPages)
	warnChan := make(chan error, totalPages)
	for p := 2; p <= totalPages; p++ {
		wg.Add(1)

		go func(reportsChan chan<- []gitlab.Project) {
			defer wg.Done()
			log.Info().Str("path", path).Int("page", p).Msg("Fetching projects of next page")
			projectPtrs, _, err := s.client.ListGroupProjects(path,
				&gitlab.ListGroupProjectsOptions{
					Archived:         gitlab.Ptr(false),
					Simple:           gitlab.Ptr(true),
					IncludeSubGroups: gitlab.Ptr(true),
					WithShared:       gitlab.Ptr(false),
					ListOptions: gitlab.ListOptions{
						Page: p,
					},
				})
			if err != nil {
				log.Error().Err(err).Str("path", path).Int("page", p).Msg("Failed to fetch projects of next page, these projects will be missing.")
				warnChan <- err
			}

			projects, errCount := dereferenceProjectsPointers(projectPtrs)
			if errCount > 0 {
				log.Warn().Str("path", path).Int("page", p).Int("count", errCount).Msg("Found nil projects, skipping them.")
			}

			nextProjectsChan <- projects
		}(nextProjectsChan)
	}
	wg.Wait()
	close(nextProjectsChan)
	close(warnChan)

	// Collect projects
	for nextProjects := range nextProjectsChan {
		projects = append(projects, nextProjects...)
	}

	// Collect warnings
	for w := range warnChan {
		warn = errors.Join(w, warn)
	}

	return
}

func filterUniqueProjects(projects []repository.Project) (filteredProjects []repository.Project) {
	projectsNamespaces := make(map[int]bool)

	for _, project := range projects {
		if _, ok := projectsNamespaces[project.ID]; !ok {
			projectsNamespaces[project.ID] = true
			filteredProjects = append(filteredProjects, project)
		}
	}

	return
}

func dereferenceProjectsPointers(projects []*gitlab.Project) (filteredProjects []gitlab.Project, errCount int) {
	for _, project := range projects {
		if project == nil {
			errCount++
			continue
		}
		filteredProjects = append(filteredProjects, *project)
	}

	return
}

func mapProject(p gitlab.Project) repository.Project {
	return repository.Project{
		ID:         p.ID,
		Name:       p.Name,
		Slug:       p.Path,
		Path:       p.PathWithNamespace,
		WebURL:     p.WebURL,
		RepoUrl:    p.HTTPURLToRepo,
		Repository: repository.Gitlab,
	}
}

func mapIssue(i gitlab.Issue) repository.Issue {
	return repository.Issue{
		Title:  i.Title,
		WebURL: i.WebURL,
	}
}

func mapIssuePtr(i *gitlab.Issue) *repository.Issue {
	if i == nil {
		return nil
	}

	issue := mapIssue(*i)

	return &issue
}

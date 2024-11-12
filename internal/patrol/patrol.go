package patrol

import (
	"errors"
	"fmt"
	"os"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/publish"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	gogitlab "github.com/xanzy/go-gitlab"
)

const tempScanDir = "tmp_scans"

// securityPatroller is the interface of the main security scanner service of this tool.
type securityPatroller interface {
	// Scans a given GitLab group path, creates and publishes the necessary reports
	Patrol(targetGroupPath string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error
}

// sheriffService is the implementation of the SecurityPatroller interface.
// It contains the main "loop" logic of this tool.
type sheriffService struct {
	gitlabService gitlab.IService
	slackService  slack.IService
	gitService    git.IService
	osvService    scanner.VulnScanner[scanner.OsvReport]
}

func New(gitlabService gitlab.IService, slackService slack.IService, gitService git.IService, osvService scanner.VulnScanner[scanner.OsvReport]) securityPatroller {
	return &sheriffService{
		gitlabService: gitlabService,
		slackService:  slackService,
		gitService:    gitService,
		osvService:    osvService,
	}
}

func (s *sheriffService) Patrol(targetGroupPath string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error {
	groupPath, err := parseGroupPaths(targetGroupPath)
	if err != nil {
		return errors.Join(errors.New("failed to parse gitlab group path"), err)
	}

	scanReports, err := s.scanAndGetReports(groupPath)
	if err != nil {
		return errors.Join(errors.New("failed to scan projects"), err)
	}

	if gitlabIssue {
		log.Info().Str("group", targetGroupPath).Msg("Creating issue in affected projects")
		publish.PublishAsGitlabIssues(scanReports, s.gitlabService)
	}

	if s.slackService != nil && slackChannel != "" {
		log.Info().Str("group", targetGroupPath).Str("slackChannel", slackChannel).Msg("Posting report to slack channel")

		if err := publish.PublishAsSlackMessage(slackChannel, scanReports, targetGroupPath, s.slackService); err != nil {
			log.Error().Err(err).Str("group", targetGroupPath).Msg("Failed to post slack report")
		}
	}

	publish.PublishToConsole(scanReports, printReport)

	return nil
}

func (s *sheriffService) scanAndGetReports(groupPath []string) (reports []*scanner.Report, err error) {
	// Create a temporary directory to store the scans
	err = os.MkdirAll(tempScanDir, os.ModePerm)
	if err != nil {
		return nil, errors.New("could not create temporary directory")
	}
	defer os.RemoveAll(tempScanDir)
	log.Info().Str("path", tempScanDir).Msg("Created temporary directory")
	log.Info().Strs("groups", groupPath).Msg("Getting the list of projects to scan")

	projects, err := s.gitlabService.GetProjectList(groupPath)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("could not get project list of group %v", groupPath), err)
	}

	// Scan all projects in parallel
	var wg sync.WaitGroup
	reportsChan := make(chan *scanner.Report, len(projects))
	for _, project := range projects {
		wg.Add(1)
		go func(reportsChan chan<- *scanner.Report) {
			log.Info().Str("project", project.Name).Msg("Scanning project")
			if report, err := s.scanProject(project); err != nil {
				log.Error().Err(err).Str("project", project.Name).Msg("Failed to scan project, skipping.")
				reportsChan <- &scanner.Report{Project: project, Error: true}
			} else {
				reportsChan <- report
			}
			defer wg.Done()
		}(reportsChan)
	}
	wg.Wait()
	close(reportsChan)

	// Collect the reports
	for r := range reportsChan {
		reports = append(reports, r)
	}

	sort.Slice(reports, func(i int, j int) bool {
		return len(reports[i].Vulnerabilities) > len(reports[j].Vulnerabilities)
	})

	return
}

// scanProject scans a project for vulnerabilities using the osv scanner.
func (s *sheriffService) scanProject(project *gogitlab.Project) (report *scanner.Report, err error) {
	dir, err := os.MkdirTemp(tempScanDir, fmt.Sprintf("%v-", project.Name))
	if err != nil {
		return nil, errors.Join(errors.New("failed to create project temporary directory"), err)
	}
	defer os.RemoveAll(dir)

	// Clone the project
	log.Info().Str("project", project.Name).Str("dir", dir).Msg("Cloning project")
	if err = s.gitService.Clone(dir, project.HTTPURLToRepo); err != nil {
		return nil, errors.Join(errors.New("failed to clone project"), err)
	}

	// Scan the project
	log.Info().Str("project", project.Name).Msg("Running osv-scanner")
	osvReport, err := s.osvService.Scan(dir)
	if err != nil {
		log.Error().Err(err).Str("project", project.Name).Msg("Failed to run osv-scanner")
		return nil, errors.Join(errors.New("failed to run osv-scanner"), err)
	}

	r := s.osvService.GenerateReport(project, osvReport)
	log.Info().Str("project", project.Name).Msg("Finished scanning with osv-scanner")

	return &r, nil
}

func parseGroupPaths(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("gitlab path missing: %v", path)
	}

	paths := strings.Split(path, "/")
	if len(paths) == 0 {
		return nil, fmt.Errorf("gitlab path incomplete: %v", path)
	}

	return paths, nil
}

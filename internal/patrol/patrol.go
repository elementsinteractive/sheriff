// Package patrol provides a service to scan GitLab groups for vulnerabilities and publish reports.
package patrol

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/publish"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"sort"
	"sync"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	gogitlab "github.com/xanzy/go-gitlab"
)

const tempScanDir = "tmp_scans"
const projectConfigFileName = "sheriff.toml"

type PlatformType string

const (
	Gitlab PlatformType = "gitlab"
	Github PlatformType = "github"
)

type ProjectLocation struct {
	Type PlatformType
	Path string
}

// PatrolArgs is a struct to store the arguments for the main patrol function.
type PatrolArgs struct {
	Locations             []ProjectLocation
	ReportToEmails        []string
	ReportToSlackChannel  string
	ReportToIssue         bool
	EnableProjectReportTo bool
	SilentReport          bool
	Verbose               bool
}

// securityPatroller is the interface of the main security scanner service of this tool.
type securityPatroller interface {
	// Scans the given Gitlab groups and projects, creates and publishes the necessary reports
	Patrol(args PatrolArgs) (warn error, err error)
}

// sheriffService is the implementation of the SecurityPatroller interface.
type sheriffService struct {
	gitlabService gitlab.IService
	slackService  slack.IService
	gitService    git.IService
	osvService    scanner.VulnScanner[scanner.OsvReport]
}

// New creates a new securityPatroller service.
// It contains the main "loop" logic of this tool.
// A "patrol" is defined as scanning GitLab groups for vulnerabilities and publishing reports where needed.
func New(gitlabService gitlab.IService, slackService slack.IService, gitService git.IService, osvService scanner.VulnScanner[scanner.OsvReport]) securityPatroller {
	return &sheriffService{
		gitlabService: gitlabService,
		slackService:  slackService,
		gitService:    gitService,
		osvService:    osvService,
	}
}

// Patrol scans the given Gitlab groups and projects, creates and publishes the necessary reports.
func (s *sheriffService) Patrol(args PatrolArgs) (warn error, err error) {
	scanReports, swarn, err := s.scanAndGetReports(args.Locations)
	if err != nil {
		return nil, errors.Join(errors.New("failed to scan projects"), err)
	}
	if swarn != nil {
		swarn = errors.Join(errors.New("errors occured when scanning projects"), swarn)
		warn = errors.Join(swarn, warn)
	}

	if len(scanReports) == 0 {
		log.Warn().Msg("No reports found. Check if projects and group paths are correct, and check the logs for any earlier errors.")
		return swarn, nil
	}

	if args.ReportToIssue {
		log.Info().Msg("Creating issue in affected projects")
		if gwarn := publish.PublishAsGitlabIssues(scanReports, s.gitlabService); gwarn != nil {
			gwarn = errors.Join(errors.New("errors occured when creating issues"), gwarn)
			warn = errors.Join(gwarn, warn)
		}

	}

	if s.slackService != nil {
		if args.ReportToSlackChannel != "" {
			log.Info().Str("slackChannel", args.ReportToSlackChannel).Msg("Posting report to slack channel")

			paths := pie.Map(args.Locations, func(v ProjectLocation) string { return v.Path })
			if err := publish.PublishAsGeneralSlackMessage(args.ReportToSlackChannel, scanReports, paths, s.slackService); err != nil {
				log.Error().Err(err).Msg("Failed to post slack report")
				err = errors.Join(errors.New("failed to post slack report"), err)
				warn = errors.Join(err, warn)
			}
		}

		if args.EnableProjectReportTo {
			log.Info().Msg("Posting report to project slack channel")
			if swarn := publish.PublishAsSpecificChannelSlackMessage(scanReports, s.slackService); swarn != nil {
				swarn = errors.Join(errors.New("errors occured when posting to project slack channel"), swarn)
				warn = errors.Join(swarn, warn)
			}

		}
	}

	publish.PublishToConsole(scanReports, args.SilentReport)

	return warn, nil
}

func (s *sheriffService) scanAndGetReports(locations []ProjectLocation) (reports []scanner.Report, warn error, err error) {
	// Create a temporary directory to store the scans
	err = os.MkdirAll(tempScanDir, os.ModePerm)
	if err != nil {
		return nil, nil, errors.New("could not create temporary directory")
	}
	defer os.RemoveAll(tempScanDir)
	log.Info().Str("path", tempScanDir).Msg("Created temporary directory")

	gitlabLocs := pie.Map(
		pie.Filter(locations, func(v ProjectLocation) bool { return v.Type == Gitlab }),
		func(v ProjectLocation) string { return v.Path },
	)
	log.Info().Strs("locations", gitlabLocs).Msg("Getting the list of projects to scan")

	projects, pwarn := s.gitlabService.GetProjectList(gitlabLocs)
	if pwarn != nil {
		pwarn = errors.Join(errors.New("errors occured when getting project list"), pwarn)
		warn = errors.Join(pwarn, warn)
	}

	// Scan all projects in parallel
	var wg sync.WaitGroup
	reportsChan := make(chan scanner.Report, len(projects))
	for _, project := range projects {
		wg.Add(1)
		go func(reportsChan chan<- scanner.Report) {
			defer wg.Done()
			log.Info().Str("project", project.Name).Msg("Scanning project")
			if report, err := s.scanProject(project); err != nil {
				log.Error().Err(err).Str("project", project.Name).Msg("Failed to scan project, skipping.")
				err = errors.Join(fmt.Errorf("failed to scan project %v", project.Name), err)
				warn = errors.Join(err, warn)
				reportsChan <- scanner.Report{Project: project, Error: true}
			} else {
				reportsChan <- *report
			}
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
func (s *sheriffService) scanProject(project gogitlab.Project) (report *scanner.Report, err error) {
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

	config, found, err := getConfiguration(path.Join(dir, projectConfigFileName))
	if err != nil {
		log.Error().Err(err).Str("project", project.PathWithNamespace).Msg("Failed to read project configuration. Running with empty configuration.")
	} else if found {
		log.Info().Str("project", project.PathWithNamespace).Msg("Found project configuration")
	} else {
		log.Info().Str("project", project.PathWithNamespace).Msg("No project configuration found. Using default")
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

	r.ProjectConfig = config

	markVulnsAsAcknowledgedInReport(&r, config)
	return &r, nil
}

// markVulnsAsAcknowledgedInReport marks vulnerabilities as acknowledged in the report
// if the user has acknowledged them in the project configuration.
// It modifies the given report in place.
func markVulnsAsAcknowledgedInReport(report *scanner.Report, config scanner.ProjectConfig) {
	ackCodes := make(map[string]bool, len(config.Acknowledged))
	AckReasons := make(map[string]string, len(config.Acknowledged))
	for _, ack := range config.Acknowledged {
		ackCodes[ack.Code] = true
		AckReasons[ack.Code] = ack.Reason
	}

	for i, v := range report.Vulnerabilities {
		if _, ok := ackCodes[v.Id]; ok {
			// We override the severity kind
			report.Vulnerabilities[i].SeverityScoreKind = scanner.Acknowledged
			if _, ok := AckReasons[v.Id]; ok {
				report.Vulnerabilities[i].AckReason = AckReasons[v.Id]
			}
		}
	}
}

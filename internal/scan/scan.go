package scan

import (
	"errors"
	"fmt"
	"securityscanner/internal/git"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/osv"
	"securityscanner/internal/report"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"
	"strings"

	"github.com/rs/zerolog/log"
)

type IService interface {
	Scan(targetGroupPath string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error
}

type service struct {
	gitlabService gitlab.IService
	slackService  slack.IService
	gitService    git.IService
	osvService    osv.IService
}

func NewService(gitlabService gitlab.IService, slackService slack.IService, gitService git.IService, osvService osv.IService) IService {
	return &service{
		gitlabService: gitlabService,
		slackService:  slackService,
		gitService:    gitService,
		osvService:    osvService,
	}
}

func (s *service) Scan(targetGroupPath string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error {
	groupPath, err := parseGroupPaths(targetGroupPath)
	if err != nil {
		return errors.Join(errors.New("failed to parse gitlab group path"), err)
	}

	scanReports, err := scanner.Scan(groupPath, s.gitlabService, s.gitService, s.osvService)
	if err != nil {
		return errors.Join(errors.New("failed to scan projects"), err)
	}

	if gitlabIssue {
		log.Info().Msg("Creating issue in affected projects")
		report.CreateGitlabIssues(scanReports, s.gitlabService)
	}

	if s.slackService != nil && slackChannel != "" {
		log.Info().Msgf("Posting report to slack channel %v", slackChannel)

		if err := report.PostSlackReport(slackChannel, scanReports, targetGroupPath, s.slackService); err != nil {
			log.Err(err).Msg("Failed to post slack report")
		}
	}

	if printReport {
		log.Info().Msgf("%#v", scanReports)
	}

	return nil
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
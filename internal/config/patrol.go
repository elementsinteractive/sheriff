package config

import (
	"errors"
	"fmt"
	"net/url"
)

type PlatformType string

const (
	Gitlab PlatformType = "gitlab"
	Github PlatformType = "github"
)

type ProjectLocation struct {
	Type PlatformType
	Path string
}

type PatrolConfig struct {
	Locations             []ProjectLocation
	ReportToEmails        []string
	ReportToSlackChannel  string
	ReportToIssue         bool
	EnableProjectReportTo bool
	SilentReport          bool
	Verbose               bool
}

type PatrolCLIOpts struct {
	Urls                  []string
	ReportToEmails        []string
	ReportToSlackChannel  string
	ReportToIssue         bool
	EnableProjectReportTo bool
	SilentReport          bool
	Verbose               bool
}

func GetPatrolConfiguration(cliOpts PatrolCLIOpts) (patrolConfig PatrolConfig, err error) {
	// Parse options
	locations, err := parseUrls(cliOpts.Urls)
	if err != nil {
		return patrolConfig, errors.Join(errors.New("failed to parse `--url` options"), err)
	}

	patrolConfig = PatrolConfig{
		Locations:             locations,
		ReportToIssue:         cliOpts.ReportToIssue,
		ReportToEmails:        cliOpts.ReportToEmails,
		ReportToSlackChannel:  cliOpts.ReportToSlackChannel,
		EnableProjectReportTo: cliOpts.EnableProjectReportTo,
		SilentReport:          cliOpts.SilentReport,
		Verbose:               cliOpts.Verbose,
	}

	return
}

func parseUrls(uris []string) ([]ProjectLocation, error) {
	locations := make([]ProjectLocation, len(uris))
	for i, uri := range uris {
		parsed, err := url.Parse(uri)
		if err != nil || parsed == nil {
			return nil, errors.Join(fmt.Errorf("failed to parse uri"), err)
		}

		if !parsed.IsAbs() {
			return nil, fmt.Errorf("url missing platform scheme %v", uri)
		}

		if parsed.Scheme == string(Github) {
			return nil, fmt.Errorf("github is currently unsupported, but is on our roadmap 😃") // TODO #9
		} else if parsed.Scheme != string(Gitlab) {
			return nil, fmt.Errorf("unsupported platform %v", parsed.Scheme)
		}

		path, err := url.JoinPath(parsed.Host, parsed.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to join host and path %v", uri)
		}

		locations[i] = ProjectLocation{
			Type: PlatformType(parsed.Scheme),
			Path: path,
		}
	}

	return locations, nil
}

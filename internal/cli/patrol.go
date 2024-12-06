package cli

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/patrol"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"strings"

	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

type CommandCategory string

const (
	Reporting     CommandCategory = "Reporting (configurable by file):"
	Tokens        CommandCategory = "Tokens:"
	Miscellaneous CommandCategory = "Miscellaneous:"
	Scanning      CommandCategory = "Scanning (configurable by file):"
)

const configFlag = "config"
const verboseFlag = "verbose"
const urlFlag = "url"
const reportToEmailFlag = "report-to-email"
const reportToIssueFlag = "report-to-issue"
const reportToSlackChannel = "report-to-slack-channel"
const reportEnableProjectReportToFlag = "report-enable-project-report-to"
const silentReportFlag = "silent"
const gitlabTokenFlag = "gitlab-token"
const slackTokenFlag = "slack-token"

var sensitiveFlags = []string{gitlabTokenFlag, slackTokenFlag}
var necessaryScanners = []string{scanner.OsvCommandName}

var PatrolFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    configFlag,
		Aliases: []string{"c"},
		Value:   "sheriff.toml",
	},
	&cli.BoolFlag{
		Name:     verboseFlag,
		Aliases:  []string{"v"},
		Usage:    "Enable verbose logging",
		Category: string(Miscellaneous),
		Value:    false,
	},
	altsrc.NewStringSliceFlag(&cli.StringSliceFlag{
		Name:     urlFlag,
		Usage:    "Groups and projects to scan for vulnerabilities (list argument which can be repeated)",
		Category: string(Scanning),
	}),
	altsrc.NewStringSliceFlag(&cli.StringSliceFlag{
		Name:     reportToEmailFlag,
		Usage:    "Enable reporting to the provided list of emails",
		Category: string(Reporting),
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     reportToIssueFlag,
		Usage:    "Enable or disable reporting to the project's issue on the associated platform (gitlab, github, ...)",
		Category: string(Reporting),
	}),
	altsrc.NewStringFlag(&cli.StringFlag{
		Name:     reportToSlackChannel,
		Usage:    "Enable reporting to the provided slack channel",
		Category: string(Reporting),
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     reportEnableProjectReportToFlag,
		Usage:    "Enable project-level configuration for '--report-to-*'.",
		Category: string(Reporting),
		Value:    true,
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     silentReportFlag,
		Usage:    "Disable report output to stdout.",
		Category: string(Reporting),
		Value:    false,
	}),
	// Secret tokens
	&cli.StringFlag{
		Name:     gitlabTokenFlag,
		Usage:    "Token to access the Gitlab API.",
		Required: true,
		EnvVars:  []string{"GITLAB_TOKEN"},
		Category: string(Tokens),
	},
	&cli.StringFlag{
		Name:     slackTokenFlag,
		Usage:    "Token to access the Slack API.",
		EnvVars:  []string{"SLACK_TOKEN"},
		Category: string(Tokens),
	},
}

func PatrolAction(cCtx *cli.Context) error {
	verbose := cCtx.Bool(verboseFlag)

	// Parse options
	locations, err := parseUrls(cCtx.StringSlice(urlFlag))
	if err != nil {
		return errors.Join(errors.New("failed to parse `--url` options"), err)
	}

	// Create services
	gitlabService, err := gitlab.New(cCtx.String(gitlabTokenFlag))
	if err != nil {
		return errors.Join(errors.New("failed to create GitLab service"), err)
	}

	slackService, err := slack.New(cCtx.String(slackTokenFlag), verbose)
	if err != nil {
		return errors.Join(errors.New("failed to create Slack service"), err)
	}

	gitService := git.New(cCtx.String(gitlabTokenFlag))
	osvService := scanner.NewOsvScanner()

	patrolService := patrol.New(gitlabService, slackService, gitService, osvService)

	// Check whether the necessary scanners are available
	missingScanners := getMissingScanners(necessaryScanners)
	if len(missingScanners) > 0 {
		return fmt.Errorf("Cannot find all necessary scanners in $PATH, missing: %v", strings.Join(missingScanners, ", "))
	}

	// Do the patrol
	if warn, err := patrolService.Patrol(
		patrol.PatrolArgs{
			Locations:             locations,
			ReportToIssue:         cCtx.Bool(reportToIssueFlag),
			ReportToEmails:        cCtx.StringSlice(reportToEmailFlag),
			ReportToSlackChannel:  cCtx.String(reportToSlackChannel),
			EnableProjectReportTo: cCtx.Bool(reportEnableProjectReportToFlag),
			SilentReport:          cCtx.Bool(silentReportFlag),
			Verbose:               verbose,
		},
	); err != nil {
		return errors.Join(errors.New("failed to scan"), err)
	} else if warn != nil {
		return cli.Exit("Patrol was partially successful, some errors occurred. Check the logs for more information.", 1)
	}

	return nil
}

func parseUrls(uris []string) ([]patrol.ProjectLocation, error) {
	locations := make([]patrol.ProjectLocation, len(uris))
	for i, uri := range uris {
		parsed, err := url.Parse(uri)
		if err != nil || parsed == nil {
			return nil, errors.Join(fmt.Errorf("failed to parse uri"), err)
		}

		if !parsed.IsAbs() {
			return nil, fmt.Errorf("url missing platform scheme %v", uri)
		}

		if parsed.Scheme == string(patrol.Github) {
			return nil, fmt.Errorf("github is currently unsupported, but is on our roadmap 😃") // TODO #9
		} else if parsed.Scheme != string(patrol.Gitlab) {
			return nil, fmt.Errorf("unsupported platform %v", parsed.Scheme)
		}

		path, err := url.JoinPath(parsed.Host, parsed.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to join host and path %v", uri)
		}

		locations[i] = patrol.ProjectLocation{
			Type: patrol.PlatformType(parsed.Scheme),
			Path: path,
		}
	}

	return locations, nil
}

func getMissingScanners(necessary []string) []string {
	missingScanners := make([]string, 0, len(necessary))
	for _, scanner := range necessary {
		if _, err := exec.LookPath(scanner); err != nil {
			missingScanners = append(missingScanners, scanner)
		}
	}

	return missingScanners
}

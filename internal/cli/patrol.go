package cli

import (
	"errors"
	"fmt"
	"os/exec"
	"sheriff/internal/config"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/patrol"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"strings"

	"github.com/urfave/cli/v2"
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
const targetFlag = "target"
const reportToEmailFlag = "report-to-email"
const reportToIssueFlag = "report-to-issue"
const reportToSlackChannel = "report-to-slack-channel"
const reportEnableProjectReportToFlag = "report-enable-project-report-to"
const silentReportFlag = "silent"
const gitlabTokenFlag = "gitlab-token"
const slackTokenFlag = "slack-token"

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
	&cli.StringSliceFlag{
		Name:     targetFlag,
		Usage:    "Groups and projects to scan for vulnerabilities (list argument which can be repeated)",
		Category: string(Scanning),
	},
	&cli.StringSliceFlag{
		Name:     reportToEmailFlag,
		Usage:    "Enable reporting to the provided list of emails",
		Category: string(Reporting),
	},
	&cli.BoolFlag{
		Name:     reportToIssueFlag,
		Usage:    "Enable or disable reporting to the project's issue on the associated platform (gitlab, github, ...)",
		Category: string(Reporting),
	},
	&cli.StringSliceFlag{
		Name:     reportToSlackChannel,
		Usage:    "Enable reporting to the provided slack channels",
		Category: string(Reporting),
	},
	&cli.BoolFlag{
		Name:     reportEnableProjectReportToFlag,
		Usage:    "Enable project-level configuration for '--report-to-*'.",
		Category: string(Reporting),
		Value:    true,
	},
	&cli.BoolFlag{
		Name:     silentReportFlag,
		Usage:    "Disable report output to stdout.",
		Category: string(Reporting),
		Value:    false,
	},
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
	config, err := config.GetPatrolConfiguration(config.PatrolCLIOpts{
		PatrolCommonOpts: config.PatrolCommonOpts{
			Targets: getStringSliceIfSet(cCtx, targetFlag),
			Report: config.PatrolReportOpts{
				To: config.PatrolReportToOpts{
					Issue:                 getBoolIfSet(cCtx, reportToIssueFlag),
					Emails:                getStringSliceIfSet(cCtx, reportToEmailFlag),
					SlackChannels:         getStringSliceIfSet(cCtx, reportToSlackChannel),
					EnableProjectReportTo: getBoolIfSet(cCtx, reportEnableProjectReportToFlag),
				},
				SilentReport: getBoolIfSet(cCtx, silentReportFlag),
			},
		},
		Config:  cCtx.String(configFlag),
		Verbose: cCtx.Bool(verboseFlag),
	})
	if err != nil {
		return errors.Join(errors.New("failed to get patrol configuration"), err)
	}

	// Get tokens
	gitlabToken := cCtx.String(gitlabTokenFlag)
	slackToken := cCtx.String(slackTokenFlag)

	// Create services
	gitlabService, err := gitlab.New(gitlabToken)
	if err != nil {
		return errors.Join(errors.New("failed to create GitLab service"), err)
	}

	slackService, err := slack.New(slackToken, config.Verbose)
	if err != nil {
		return errors.Join(errors.New("failed to create Slack service"), err)
	}

	gitService := git.New(gitlabToken)
	osvService := scanner.NewOsvScanner()

	patrolService := patrol.New(gitlabService, slackService, gitService, osvService)

	// Check whether the necessary scanners are available
	missingScanners := getMissingScanners(necessaryScanners)
	if len(missingScanners) > 0 {
		return fmt.Errorf("cannot find all necessary scanners in $PATH, missing: %v", strings.Join(missingScanners, ", "))
	}

	// Do the patrol
	if warn, err := patrolService.Patrol(config); err != nil {
		return errors.Join(errors.New("failed to scan"), err)
	} else if warn != nil {
		return cli.Exit("Patrol was partially successful, some errors occurred. Check the logs for more information.", 1)
	}

	return nil
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

package cli

import (
	"errors"
	"fmt"
	"regexp"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/patrol"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"

	zerolog "github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

// Regexes very loosely defined based on GitLab's reserved names:
// https://docs.gitlab.com/ee/user/reserved_names.html#limitations-on-usernames-project-and-group-names-and-slugs
// In reality the regex should be more restrictive about special characters, for now we're just checking for slashes and non-whitespace characters.
const groupPathRegex = "^\\S+(\\/\\S+)*$"   // Matches paths like "group" or "group/subgroup" ...
const projectPathRegex = "^\\S+(\\/\\S+)+$" // Matches paths like "group/project" or "group/subgroup/project" ...

type CommandCategory string

const (
	Reporting     CommandCategory = "Reporting (configurable by file):"
	Tokens        CommandCategory = "Tokens:"
	Miscellaneous CommandCategory = "Miscellaneous:"
	Scanning      CommandCategory = "Scanning (configurable by file):"
)

const configFlag = "config"
const verboseFlag = "verbose"
const testingFlag = "testing"
const groupsFlag = "gitlab-groups"
const projectsFlag = "gitlab-projects"
const reportSlackChannelFlag = "report-slack-channel"
const reportSlackProjectChannelFlag = "report-slack-project-channel"
const reportGitlabFlag = "report-gitlab-issue"
const silentReport = "silent"
const publicSlackChannelFlag = "public-slack-channel"
const gitlabTokenFlag = "gitlab-token"
const slackTokenFlag = "slack-token"

var sensitiveFlags = []string{gitlabTokenFlag, slackTokenFlag}

var PatrolFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  configFlag,
		Value: "sheriff.toml",
	},
	&cli.BoolFlag{
		Name:     verboseFlag,
		Usage:    "Enable verbose logging",
		Category: string(Miscellaneous),
		Value:    false,
	},
	altsrc.NewStringSliceFlag(&cli.StringSliceFlag{
		Name:     groupsFlag,
		Usage:    "Gitlab groups to scan for vulnerabilities (list argument which can be repeated)",
		Category: string(Scanning),
		Action:   validatePaths(groupPathRegex),
	}),
	altsrc.NewStringSliceFlag(&cli.StringSliceFlag{
		Name:     projectsFlag,
		Usage:    "Gitlab projects to scan for vulnerabilities (list argument which can be repeated)",
		Category: string(Scanning),
		Action:   validatePaths(projectPathRegex),
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     testingFlag,
		Usage:    "Enable testing mode. This can enable features that are not safe for production use.",
		Category: string(Miscellaneous),
		Value:    false,
	}),
	altsrc.NewStringFlag(&cli.StringFlag{
		Name:     reportSlackChannelFlag,
		Usage:    "Enable reporting to Slack through messages in the specified channel.",
		Category: string(Reporting),
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     reportSlackProjectChannelFlag,
		Usage:    "Enable reporting to Slack through messages in the specified project's channel. Requires a project-level configuration file specifying the channel.",
		Category: string(Reporting),
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     reportGitlabFlag,
		Usage:    "Enable reporting to GitLab through issue creation in projects affected by vulnerabilities.",
		Category: string(Reporting),
		Value:    false,
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     silentReport,
		Usage:    "Disable report output to stdout.",
		Category: string(Reporting),
		Value:    false,
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     publicSlackChannelFlag,
		Usage:    "Allow the slack report to be posted to a public channel. Note that reports may contain sensitive information which should not be disclosed on a public channel, for this reason this flag will only be enabled when combined with the testing flag.",
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

	var publicChannelsEnabled bool
	if cCtx.Bool(testingFlag) {
		zerolog.Warn().Msg("Testing mode enabled. This may enable features that are not safe for production use.")
		publicChannelsEnabled = cCtx.Bool(publicSlackChannelFlag)
	}

	// Create services
	gitlabService, err := gitlab.New(cCtx.String(gitlabTokenFlag))
	if err != nil {
		return errors.Join(errors.New("failed to create GitLab service"), err)
	}

	slackService, err := slack.New(cCtx.String(slackTokenFlag), publicChannelsEnabled, verbose)
	if err != nil {
		return errors.Join(errors.New("failed to create Slack service"), err)
	}

	gitService := git.New(cCtx.String(gitlabTokenFlag))
	osvService := scanner.NewOsvScanner()

	patrolService := patrol.New(gitlabService, slackService, gitService, osvService)

	// Do the patrol
	if warn, err := patrolService.Patrol(
		cCtx.StringSlice(groupsFlag),
		cCtx.StringSlice(projectsFlag),
		cCtx.Bool(reportGitlabFlag),
		cCtx.String(reportSlackChannelFlag),
		cCtx.Bool(reportSlackProjectChannelFlag),
		cCtx.Bool(silentReport),
		verbose,
	); err != nil {
		return errors.Join(errors.New("failed to scan"), err)
	} else if warn != nil {
		return cli.Exit("Patrol was partially successful, some errors occurred. Check the logs for more information.", 1)
	}

	return nil
}

func validatePaths(regex string) func(*cli.Context, []string) error {
	return func(_ *cli.Context, groups []string) (err error) {
		rgx, err := regexp.Compile(regex)
		if err != nil {
			return err
		}

		for _, path := range groups {
			matched := rgx.Match([]byte(path))

			if !matched {
				return fmt.Errorf("invalid group path: %v", path)
			}
		}
		return
	}
}

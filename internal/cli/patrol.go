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
	"slices"
	"strings"

	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

const gitlabPathRegex = "^\\S+(\\/\\S+)+$"

type CommandCategory string

const (
	Reporting     CommandCategory = "Reporting (configurable by file):"
	Tokens        CommandCategory = "Tokens:"
	Miscellaneous CommandCategory = "Miscellaneous:"
	Scanning      CommandCategory = "Scanning (configurable by file):"

	// TODO: Figure out how to use custom types with a generic URL validator/parser
	Gitlab string = "gitlab"
	Issue  string = "issue"
	Slack  string = "slack"
)

var sourceCodePlatforms = []string{Gitlab}
var reportToPlatforms = []string{Slack, Issue}

var platformUrlRegex = map[string]string{
	Gitlab: gitlabPathRegex,
	Slack:  "^[a-z0-9-]{1}[a-z0-9-]{0,20}$",
	Issue:  "^$",
}

const configFlag = "config"
const verboseFlag = "verbose"
const urlFlag = "url"
const reportToFlag = "report-to"
const enableProjectReportToFlag = "enable-project-report-to"
const silentReportFlag = "silent"
const gitlabTokenFlag = "gitlab-token"
const slackTokenFlag = "slack-token"

var sensitiveFlags = []string{gitlabTokenFlag, slackTokenFlag}

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
		Action:   validateURLs(sourceCodePlatforms),
	}),
	altsrc.NewStringSliceFlag(&cli.StringSliceFlag{
		Name:     reportToFlag,
		Usage:    "Enable reporting to specified messaging service & name. In the format: 'service:name'.",
		Category: string(Reporting),
		Action:   validateURLs(reportToPlatforms),
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     enableProjectReportToFlag,
		Usage:    "Enable project-level configuration for '--report-to'.",
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

	var publicChannelsEnabled bool

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

	// Run the scan
	toScan, err := parseURLs(cCtx.StringSlice(urlFlag))
	if err != nil {
		return errors.Join(errors.New("failed to parse URLs"), err)
	}

	toReport, err := parseURLs(cCtx.StringSlice(reportToFlag))
	if err != nil {
		return errors.Join(errors.New("failed to parse report URLs"), err)
	}

	if warn, err := patrolService.Patrol(
		patrol.PatrolArgs{
			ToScanUrls:   toScan,
			ToReportUrls: toReport,
			SilentReport: cCtx.Bool(silentReportFlag),
			Verbose:      verbose,
		},
	); err != nil {
		return errors.Join(errors.New("failed to scan"), err)
	} else if warn != nil {
		return cli.Exit("Scan was partially successful, some errors occurred. Check the logs for more information.", 1)
	}

	return nil
}

// validateURLs validates the URLs passed as arguments.
// It ensures that the URL is in the format "platform:path" and that the path matches the regex for the platform.
func validateURLs(validPrefixes []string) func(_ *cli.Context, urls []string) (err error) {
	return func(_ *cli.Context, urls []string) (err error) {
		for _, url := range urls {
			parts := strings.Split(url, "://")
			if len(parts) != 2 {
				return fmt.Errorf("invalid url: %v", url)
			}

			platform := parts[0]

			if !slices.Contains(validPrefixes, platform) {
				return fmt.Errorf("Unsupported repository service: %v", platform)
			}

			regex, ok := platformUrlRegex[platform]
			if !ok {
				return fmt.Errorf("No regex for platform: %v", platform)
			}

			// Check the URL
			rgx, err := regexp.Compile(regex)
			if err != nil {
				return err
			}

			path := parts[1]
			matched := rgx.Match([]byte(path))

			if !matched {
				return fmt.Errorf("invalid group path for platform: %v for %v", path, platform)
			}

		}
		return
	}
}

// parseURLs parses the URLs passed as arguments returning a struct that
// separates the platform from the url part.
func parseURLs(urls []string) ([]patrol.GenericUrlElem, error) {
	var parsedUrls []patrol.GenericUrlElem

	for _, url := range urls {
		parts := strings.Split(url, "://")
		if len(parts) != 2 {
			// This should never happen, as the URL should have been validated before
			return nil, fmt.Errorf("invalid url: %v", url)
		}
		parsedUrls = append(parsedUrls, patrol.GenericUrlElem{
			Platform: parts[0],
			Url:      parts[1],
		})
	}

	return parsedUrls, nil
}

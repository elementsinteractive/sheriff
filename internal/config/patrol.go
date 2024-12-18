package config

import (
	"errors"
	"fmt"
	"net/url"
	"sheriff/internal/toml"

	zerolog "github.com/rs/zerolog/log"
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
	ReportToSlackChannels []string
	ReportToIssue         bool
	EnableProjectReportTo bool
	SilentReport          bool
	Verbose               bool
}

// Options common in both the CLI options & file options
type PatrolReportToOpts struct {
	Emails                *[]string `toml:"emails"`
	SlackChannels         *[]string `toml:"slack-channels"`
	Issue                 *bool     `toml:"issue"`
	EnableProjectReportTo *bool     `toml:"enable-project-report-to"`
}

type PatrolReportOpts struct {
	SilentReport *bool              `toml:"silent"`
	To           PatrolReportToOpts `toml:"to"`
}

type PatrolCommonOpts struct {
	Targets *[]string        `toml:"targets"`
	Report  PatrolReportOpts `toml:"report"`
}

// Options only available from CLI configuration
type PatrolCLIOpts struct {
	Config  string
	Verbose bool
	PatrolCommonOpts
}

// Options only available from File configuration
type PatrolFileOpts struct {
	PatrolCommonOpts
}

func GetPatrolConfiguration(cliOpts PatrolCLIOpts) (config PatrolConfig, err error) {
	zerolog.Debug().Interface("cli options", cliOpts).Msg("Running with cli options")
	var tomlOpts PatrolFileOpts
	if cliOpts.Config != "" {
		found, err := toml.GetFile(cliOpts.Config, &tomlOpts)
		if !found {
			return config, fmt.Errorf("failed to find configuration file %v", cliOpts.Config)
		} else if err != nil {
			return config, errors.Join(errors.New("failed to parse patrol configuration file"), err)
		}

		zerolog.Debug().Interface("file config", tomlOpts).Msg("Running with file configuration")
	}

	config, err = mergeConfigs(cliOpts, tomlOpts)
	if err != nil {
		return config, errors.Join(errors.New("failed to merge CLI and file config"), err)
	}

	zerolog.Info().Interface("config", config).Msg("Running with configuration")

	return
}

func mergeConfigs(cliOpts PatrolCLIOpts, fileOpts PatrolFileOpts) (config PatrolConfig, err error) {
	locations := getCliOrFileOption(cliOpts.Targets, fileOpts.Targets, []string{})
	parsedLocations, err := parseTargets(locations)
	if err != nil {
		return config, errors.Join(errors.New("could not parse targets from CLI options"), err)
	}

	config = PatrolConfig{
		Locations:             parsedLocations,
		ReportToIssue:         getCliOrFileOption(cliOpts.Report.To.Issue, fileOpts.Report.To.Issue, false),
		ReportToEmails:        getCliOrFileOption(cliOpts.Report.To.Emails, fileOpts.Report.To.Emails, []string{}),
		ReportToSlackChannels: getCliOrFileOption(cliOpts.Report.To.SlackChannels, fileOpts.Report.To.SlackChannels, []string{}),
		EnableProjectReportTo: getCliOrFileOption(cliOpts.Report.To.EnableProjectReportTo, fileOpts.Report.To.EnableProjectReportTo, false),
		SilentReport:          getCliOrFileOption(cliOpts.Report.SilentReport, fileOpts.Report.SilentReport, false),
		Verbose:               cliOpts.Verbose,
	}

	return
}

// Returns valueA if != nil, otherwise valueB if != nil, otherwise the provided default value
func getCliOrFileOption[T interface{}](valueA *T, valueB *T, def T) (r T) {
	if valueA != nil {
		return *valueA
	}

	if valueB != nil {
		return *valueB
	}

	return def
}

func parseTargets(targets []string) ([]ProjectLocation, error) {
	locations := make([]ProjectLocation, len(targets))
	for i, t := range targets {
		parsed, err := url.Parse(t)
		if err != nil || parsed == nil {
			return nil, errors.Join(fmt.Errorf("failed to parse uri"), err)
		}

		if !parsed.IsAbs() {
			return nil, fmt.Errorf("target missing platform scheme %v", t)
		}

		if parsed.Scheme == string(Github) {
			return nil, fmt.Errorf("github is currently unsupported, but is on our roadmap 😃") // TODO #9
		} else if parsed.Scheme != string(Gitlab) {
			return nil, fmt.Errorf("unsupported platform %v", parsed.Scheme)
		}

		path, err := url.JoinPath(parsed.Host, parsed.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to join host and path %v", t)
		}

		locations[i] = ProjectLocation{
			Type: PlatformType(parsed.Scheme),
			Path: path,
		}
	}

	return locations, nil
}

package config

import (
	"path"

	"github.com/rs/zerolog/log"
)

const projectConfigFileName = "sheriff.toml"

type AcknowledgedVuln struct {
	Code   string `toml:"code"`
	Reason string `toml:"reason"`
}

type ProjectReportTo struct {
	SlackChannel string `toml:"slack-channel"`
}

type ProjectReport struct {
	To ProjectReportTo `toml:"to"`
}

type ProjectConfig struct {
	Report       ProjectReport      `toml:"report"`
	SlackChannel string             `toml:"slack-channel"` // TODO #27: Break in v1.0. Kept for backwards-compatibility
	Acknowledged []AcknowledgedVuln `toml:"acknowledged"`
}

func GetProjectConfiguration(projectName string, dir string) (config ProjectConfig) {
	found, err := getTOMLFile(path.Join(dir, projectConfigFileName), &config)
	if err != nil {
		log.Error().Err(err).Str("project", projectName).Msg("Failed to read project configuration. Running with empty configuration.")
	} else if found {
		log.Info().Str("project", projectName).Msg("Found project configuration")
	} else {
		log.Info().Str("project", projectName).Msg("No project configuration found. Using default")
	}

	if config.SlackChannel != "" {
		config.Report.To.SlackChannel = config.SlackChannel
	}

	return
}

package config

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
)

type AcknowledgedVuln struct {
	Code   string `toml:"code"`
	Reason string `toml:"reason"`
}

type ProjectConfig struct {
	ReportToSlackChannel string             `toml:"report-to-slack-channel"`
	SlackChannel         string             `toml:"slack-channel"` // TODO #27: Break in v1.0. Kept for backwards-compatibility
	Acknowledged         []AcknowledgedVuln `toml:"acknowledged"`
}

func GetConfiguration(filename string) (config ProjectConfig, found bool, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return ProjectConfig{}, false, nil
	} else if err != nil {
		return config, false, errors.Join(errors.New("unexpected error when attempting to get project configuration"), err)
	}

	m, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return config, true, errors.Join(errors.New("failed to decode project configuration"), err)
	}

	if undecoded := m.Undecoded(); len(undecoded) > 0 {
		keys := pie.Map(undecoded, func(u toml.Key) string { return u.String() })

		log.Warn().Strs("keys", keys).Msg("Found undecoded keys in project configuration")
	}

	if config.SlackChannel != "" {
		config.ReportToSlackChannel = config.SlackChannel
	}

	return config, true, nil
}

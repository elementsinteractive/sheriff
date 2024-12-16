package config

import (
	"errors"
	"os"
	"sheriff/internal/scanner"

	"github.com/BurntSushi/toml"
	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
)

func GetConfiguration(filename string) (config scanner.ProjectConfig, found bool, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return scanner.ProjectConfig{}, false, nil
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

package config

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
)

// getTOMLFile parses and sets passed config pointer by value
func getTOMLFile[T interface{}](filename string, config *T) (found bool, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, errors.Join(errors.New("unexpected error when attempting to read file"), err)
	}

	m, err := toml.DecodeFile(filename, config)
	if err != nil {
		return true, errors.Join(errors.New("failed to decode TOML file"), err)
	}

	if undecoded := m.Undecoded(); len(undecoded) > 0 {
		keys := pie.Map(undecoded, func(u toml.Key) string { return u.String() })

		log.Warn().Strs("keys", keys).Msg("Found undecoded keys in TOML file")
	}

	return true, nil
}

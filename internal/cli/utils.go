package cli

import (
	"sheriff/internal/log"

	zerolog "github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func ConfigureLogs(cCtx *cli.Context) error {
	log.ConfigureLogs(cCtx.Bool(verboseFlag))
	zerolog.Info().Msg("Logging configured")
	return nil
}

func getStringSliceIfSet(cCtx *cli.Context, flagName string) *[]string {
	if cCtx.IsSet(flagName) {
		v := cCtx.StringSlice(flagName)
		return &v
	}

	return nil
}

func getStringIfSet(cCtx *cli.Context, flagName string) *string {
	if cCtx.IsSet(flagName) {
		v := cCtx.String(flagName)
		print(v)
		return &v
	}

	return nil
}

func getBoolIfSet(cCtx *cli.Context, flagName string) *bool {
	if cCtx.IsSet(flagName) {
		v := cCtx.Bool(flagName)
		return &v
	}

	return nil
}

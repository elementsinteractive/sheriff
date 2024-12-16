package cli

import (
	zerolog "github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func App(args []string) {
	app := &cli.App{
		Name:    "sheriff",
		Usage:   "Fighting dangerous dangerous dependencies since 2024.",
		Version: "0.19.2",
		Commands: []*cli.Command{
			{
				Name:  "patrol",
				Usage: "Tell sheriff to patrol a GitLab group looking for vulnerabilities",
				Description: `Sheriff will patrol a GitLab group looking for vulnerabilities in the dependencies of the projects in the group.

You can configure the behavior of Sheriff by providing various flags. (see OPTIONS)
In addition, you can create a configuration file named sheriff.toml in the current directory. Sheriff will look for this file by default, but you can specify a different configuration file with the --config flag.
This file is formatted in TOML and can contain any of the flags that can be set on the command line under the 'Reporting' category.
`,
				Flags:  PatrolFlags,
				Action: PatrolAction,
				Before: ConfigureLogs,
			},
		},
	}

	if err := app.Run(args); err != nil {
		zerolog.Fatal().Err(err).Msg("Could not run application")
	}
}

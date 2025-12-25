package cli

import (
	"fmt"

	"github.com/goodieshq/sceptune/pkg/utils"
	"github.com/urfave/cli/v3"
)

var App = cli.Command{
	Name:    "sceptune",
	Usage:   "A SCEP server for intune SCEP profile enrollment",
	Version: utils.GetSceptuneVersion(),
	Action:  run,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "verbose",
			Usage:   "Enable verbose logging output",
			Sources: cli.EnvVars("SCEPTUNE_VERBOSE"),
		},
		&cli.StringFlag{
			Name:    "tenant-id",
			Aliases: []string{"t"},
			Usage: "The Azure AD tenant ID where the Intune instance is located. " +
				"Can also be set via the SCEPTUNE_TENANT_ID environment variable.",
			Value:   "",
			Sources: cli.EnvVars("SCEPTUNE_TENANT_ID"),
		},
		&cli.StringFlag{
			Name:    "client-id",
			Aliases: []string{"c"},
			Usage: "The Azure AD client ID of the application with SCEP permissions. " +
				"Can also be set via the SCEPTUNE_CLIENT_ID environment variable.",
			Value:   "",
			Sources: cli.EnvVars("SCEPTUNE_CLIENT_ID"),
		},
		&cli.StringFlag{
			Name:    "client-secret",
			Aliases: []string{"secret", "s"},
			Usage: "The Azure AD client secret of the application with SCEP permissions. " +
				"Can also be set via the SCEPTUNE_CLIENT_SECRET environment variable.",
			Value:   "",
			Sources: cli.EnvVars("SCEPTUNE_CLIENT_SECRET"),
		},
		&cli.StringFlag{
			Name:    "client-secret-file",
			Aliases: []string{"secret-file", "S"},
			Usage: "File containing the Azure AD client secret of the application with SCEP permissions. " +
				"Can also be set via the SCEPTUNE_CLIENT_SECRET_FILE environment variable.",
			Value:   "",
			Sources: cli.EnvVars("SCEPTUNE_CLIENT_SECRET_FILE"),
		},
		&cli.Uint16Flag{
			Name:    "port",
			Aliases: []string{"p"},
			Usage: "The port to listen on for incoming SCEP requests. " +
				"Can also be set via the SCEPTUNE_PORT environment variable.",
			Value:   8080,
			Sources: cli.EnvVars("SCEPTUNE_PORT"),
			Validator: func(u uint16) error {
				if !(u > 0) {
					return fmt.Errorf("Port must be > 0, got '%d'", u)
				}
				return nil
			},
		},
		&cli.StringFlag{
			Name:      "ca-crt",
			TakesFile: true,
			Usage: "Path to the signing CA certificate file in PEM/DER format. " +
				"Can also be set via the SCEPTUNE_CA_CERT environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_CA_CERT", "SCEPTUNE_CA_CRT"),
		},
		&cli.StringFlag{
			Name:      "ra-crt",
			TakesFile: true,
			Usage: "Path to the RA certificate file in PEM/DER format. " +
				"Can also be set via the SCEPTUNE_RA_CERT environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_RA_CERT", "SCEPTUNE_RA_CRT"),
		},
		&cli.StringFlag{
			Name:      "ra-key",
			Aliases:   []string{"key", "key-file"},
			TakesFile: true,
			Usage: "Path to the RA private key file in PEM format. " +
				"Can also be set via the SCEPTUNE_RA_KEY environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_RA_KEY"),
		},
		&cli.StringFlag{
			Name:      "ca-chain",
			Aliases:   []string{"chain", "ca-chain-file"},
			TakesFile: true,
			Usage: "Path to the CA certificate chain file in PEM format. " +
				"Can also be set via the SCEPTUNE_CA_CHAIN environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_CA_CHAIN"),
		},
		&cli.StringFlag{
			Name:      "json-web-key-file",
			TakesFile: true,
			Aliases:   []string{"jwk", "jwk-file"},
			Usage: "Path to the JSON Web Key (JWK) file for signing SCEP responses. " +
				"Can also be set via the SCEPTUNE_JSON_WEB_KEY_FILE environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_JSON_WEB_KEY_FILE"),
		},
		&cli.StringFlag{
			Name:    "json-web-key-password",
			Aliases: []string{"jwk-password"},
			Usage: "Path to the JSON Web Key (JWK) file for signing SCEP responses. " +
				"Can also be set via the SCEPTUNE_JSON_WEB_KEY_PASSWORD environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_JSON_WEB_KEY_PASSWORD"),
		},
		&cli.StringFlag{
			Name:      "json-web-key-password-file",
			TakesFile: true,
			Aliases:   []string{"jwk-password-file"},
			Usage: "Path to the JSON Web Key (JWK) password file for signing SCEP responses. " +
				"Can also be set via the SCEPTUNE_JSON_WEB_KEY_PASSWORD_FILE environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_JSON_WEB_KEY_PASSWORD_FILE"),
		},
		&cli.StringFlag{
			Name:    "step-api-url",
			Aliases: []string{"step-url", "api"},
			Usage: "The URL of the Step API. " +
				"Can also be set via the SCEPTUNE_STEP_API_URL environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_STEP_API_URL"),
		},
		&cli.StringFlag{
			Name:    "step-provisioner-name",
			Aliases: []string{"provisioner-name", "provisioner"},
			Usage: "The name of the Step provisioner to use. " +
				"Can also be set via the SCEPTUNE_STEP_PROVISIONER_NAME environment variable.",
			Sources: cli.EnvVars("SCEPTUNE_STEP_PROVISIONER_NAME"),
		},
		&cli.StringFlag{
			Name: "scep-path",
			Usage: "The URL path to serve SCEP requests on. " +
				"Can also be set via the SCEPTUNE_SCEP_PATH environment variable.",
			Value:   "/scep",
			Sources: cli.EnvVars("SCEPTUNE_SCEP_PATH"),
		},
		&cli.StringFlag{
			Name: "database-path",
			Usage: "Path to the SQLite database file for storing certificate records. " +
				"Can also be set via the SCEPTUNE_DATABASE_PATH environment variable.",
			Value:   "./sceptune.db",
			Sources: cli.EnvVars("SCEPTUNE_DATABASE_PATH"),
		},
	},
}

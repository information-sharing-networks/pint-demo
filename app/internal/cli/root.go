package cli

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/information-sharing-networks/pint-demo/app/internal/config"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/information-sharing-networks/pint-demo/app/internal/version"
	"github.com/spf13/cobra"
)

var (
	cfg       *config.ServerEnvironment
	appLogger *slog.Logger
)

var rootCmd = &cobra.Command{
	Use:               "pint-client",
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Short:             "PINT API sender platform CLI",
	Long:              `PINT sender CLI for transferring eBL envelopes to receiving platforms`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		cfg, err = config.NewServerConfig()
		if err != nil {
			log.Printf("failed to load configuration: %v", err.Error())
			return err
		}

		appLogger = logger.InitLogger(logger.ParseLogLevel(cfg.LogLevel), cfg.Environment)
		return nil
	},
}

func Execute() {
	v := version.Get()
	rootCmd.Version = fmt.Sprintf("%s (built %s, commit %s)", v.Version, v.BuildDate, v.GitCommit)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(transferCmd)
	rootCmd.AddCommand(statusCmd)
}

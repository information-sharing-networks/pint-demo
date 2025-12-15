package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status <envelope-reference>",
	Short: "Check the status of an envelope transfer",
	Long:  `Query the receiver platform to check the current status of an envelope transfer`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		appLogger.Info("Status command",
			slog.String("envelope_reference", args[0]),
		)
		return fmt.Errorf("not yet implemented")
	},
}

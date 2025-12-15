package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate <receiver-code>",
	Short: "Validate a receiver before transfer",
	Long:  `Validate that a receiver platform is reachable and supports the PINT API before initiating a transfer`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		appLogger.Info("Validate command",
			slog.String("receiver_code", args[0]),
		)
		return fmt.Errorf("not yet implemented")
	},
}

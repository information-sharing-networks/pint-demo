package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var transferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Transfer an eBL envelope",
	Long:  `Initiate and manage eBL envelope transfers to receiving platforms`,
}

var transferInitiateCmd = &cobra.Command{
	Use:   "initiate <receiver-code> <ebl-file>",
	Short: "Initiate a new envelope transfer",
	Long:  `Initiate a new envelope transfer to a receiver platform`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		appLogger.Info("Initiate command",
			slog.String("receiver_code", args[0]),
			slog.String("ebl_file", args[1]),
		)
		return fmt.Errorf("not yet implemented")
	},
}

var transferAdditionalCmd = &cobra.Command{
	Use:   "additional-documents <envelope-reference> <document-file>",
	Short: "Transfer additional documents",
	Long:  `Transfer additional documents for an existing envelope`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		appLogger.Info("Additional documents command",
			slog.String("envelope_reference", args[0]),
			slog.String("document_file", args[1]),
		)
		return fmt.Errorf("not yet implemented")
	},
}

var transferCompleteCmd = &cobra.Command{
	Use:   "Complete <envelope-reference>",
	Short: "Complete an envelope transfer",
	Long:  `Signal to the receiver that all documents have been transferred`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		appLogger.Info("Complete transfer command",
			slog.String("envelope_reference", args[0]),
		)
		return fmt.Errorf("not yet implemented")
	},
}

func init() {
	transferCmd.AddCommand(transferInitiateCmd)
	transferCmd.AddCommand(transferAdditionalCmd)
	transferCmd.AddCommand(transferCompleteCmd)
}

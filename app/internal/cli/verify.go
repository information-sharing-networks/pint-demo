package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a JWS signature",
	Long: `Verify a JWS signature using a public key.

This command is useful for testing signature verification.

Example:
  pint-demo verify --signature "eyJ..." --public-key ./keys/platform-key.pub.pem`,
	RunE: runVerify,
}

var (
	signatureToVerify string
	publicKeyPath     string
)

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVar(&signatureToVerify, "signature", "", "JWS signature to verify (required)")
	verifyCmd.Flags().StringVar(&publicKeyPath, "public-key", "", "Path to public key PEM file (required)")
	verifyCmd.MarkFlagRequired("signature")
	verifyCmd.MarkFlagRequired("public-key")
}

func runVerify(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// TODO: Implement signature verification
	// 1. Load public key from PEM file using crypto.LoadPublicKeyFromPEM()
	// 2. Verify signature using crypto.VerifyJWS()
	// 3. Print payload if verification succeeds
	// 4. Print error if verification fails

	logger.Info("verifying JWS signature",
		slog.String("public_key_path", publicKeyPath))

	return fmt.Errorf("not implemented")
}


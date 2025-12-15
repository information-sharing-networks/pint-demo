package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate RSA key pair for platform signing",
	Long: `Generate a new RSA key pair for signing PINT envelopes.

The private key will be used to sign outgoing envelopes.
The public key will be published via the JWK endpoint for other platforms to verify signatures.

Example:
  pint-demo keygen --size 4096 --output ./keys/platform-key`,
	RunE: runKeygen,
}

var (
	keySize    int
	outputPath string
	keyID      string
)

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().IntVar(&keySize, "size", 4096, "RSA key size in bits (2048 or 4096)")
	keygenCmd.Flags().StringVar(&outputPath, "output", "./keys/platform-key", "Output path prefix for key files")
	keygenCmd.Flags().StringVar(&keyID, "key-id", "", "Key ID for JWK (defaults to generated UUID)")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// TODO: Implement key generation
	// 1. Validate key size (must be 2048 or 4096)
	// 2. Generate key ID if not provided (use UUID)
	// 3. Call crypto.GenerateRSAKeyPair()
	// 4. Save private key to {outputPath}.pem using crypto.SavePrivateKeyToPEM()
	// 5. Save public key to {outputPath}.pub.pem using crypto.SavePublicKeyToPEM()
	// 6. Print success message with key ID and file paths
	// 7. Print warning about keeping private key secure

	logger.Info("generating RSA key pair",
		slog.Int("key_size", keySize),
		slog.String("output_path", outputPath))

	return fmt.Errorf("not implemented")
}


// keygen is a CLI tool for generating JWK sets for testing and manual key configuration.
package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	pintcrypto "github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/version"
	"github.com/spf13/cobra"
)

// file naming convention - domain.public.jwk and domain.private.jwk
const (
	publicKeyFileNameFormat  = "%s.public.jwk"
	privateKeyFileNameFormat = "%s.private.jwk"
)

var (
	domain    string
	outputDir string
	keyType   string
	rsaSize   int
	kid       string
)

func main() {
	rootCmd := &cobra.Command{
		Use:               "keygen",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		Short:             "JWK key generator for PINT platforms",
		Long:              "Generate RSA or Ed25519 key pairs in JWK format for PINT platform testing and manual key configuration",
	}

	v := version.Get()
	rootCmd.Version = fmt.Sprintf("%s (built %s, commit %s)", v.Version, v.BuildDate, v.GitCommit)

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new key pair",
		Long:  "Generate a new RSA or Ed25519 key pair for a domain in JWK format",
		RunE:  runGenerate,
	}

	generateCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name (e.g., example.com) [required]")
	generateCmd.Flags().StringVarP(&keyType, "type", "t", "", "Key type: rsa or ed25519 [required]")
	generateCmd.Flags().StringVarP(&outputDir, "outputdir", "o", "", "Output directory for generated keys [required]")
	generateCmd.Flags().IntVarP(&rsaSize, "size", "s", 4096, "RSA key size in bits (2048 or 4096, default: 4096)")
	generateCmd.Flags().StringVarP(&kid, "kid", "k", "", "Key ID (default: auto-generated from thumbprint)")
	generateCmd.MarkFlagRequired("domain")
	generateCmd.MarkFlagRequired("type")
	generateCmd.MarkFlagRequired("outputdir")

	rootCmd.AddCommand(generateCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runGenerate(cmd *cobra.Command, args []string) error {
	if keyType != "rsa" && keyType != "ed25519" {
		return fmt.Errorf("invalid key type: %s (must be 'rsa' or 'ed25519')", keyType)
	}

	if keyType == "rsa" && rsaSize != 2048 && rsaSize != 4096 {
		return fmt.Errorf("invalid RSA key size: %d (must be 2048 or 4096)", rsaSize)
	}

	// make the directory if it doesn't exist
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}
	if keyType == "rsa" {
		return generateRSAKeys()
	}
	return generateEd25519Keys()
}

func generateRSAKeys() error {
	fmt.Printf("Generating %d-bit RSA key pair for domain: %s\n", rsaSize, domain)

	// Use our crypto package to generate the key
	privateKey, err := pintcrypto.GenerateRSAKeyPair(rsaSize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate key ID from thumbprint if not provided
	keyID := kid
	if keyID == "" {
		keyID, err = pintcrypto.GenerateKeyIDFromRSAKey(&privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to generate key ID: %w", err)
		}
	}

	// Save public key
	publicPath := filepath.Join(outputDir, fmt.Sprintf(publicKeyFileNameFormat, domain))
	if err := pintcrypto.SaveRSAPublicKeyToFile(&privateKey.PublicKey, keyID, publicPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	fmt.Printf("✓ Public JWK:  %s (kid: %s)\n", publicPath, keyID)

	// Save private key
	privatePath := filepath.Join(outputDir, fmt.Sprintf(privateKeyFileNameFormat, domain))
	if err := pintcrypto.SaveRSAPrivateKeyToFile(privateKey, keyID, privatePath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("✓ Private JWK: %s (kid: %s)\n", privatePath, keyID)

	return nil
}

func generateEd25519Keys() error {
	fmt.Printf("Generating Ed25519 key pair for domain: %s\n", domain)

	// Use our crypto package to generate the key
	privateKey, err := pintcrypto.GenerateEd25519KeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Generate key ID from thumbprint if not provided
	keyID := kid
	if keyID == "" {
		keyID, err = pintcrypto.GenerateKeyIDFromEd25519Key(publicKey)
		if err != nil {
			return fmt.Errorf("failed to generate key ID: %w", err)
		}
	}

	// Save public key
	publicPath := filepath.Join(outputDir, fmt.Sprintf(publicKeyFileNameFormat, domain))
	if err := pintcrypto.SaveEd25519PublicKeyToFile(publicKey, keyID, publicPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	fmt.Printf("✓ Public JWK:  %s (kid: %s)\n", publicPath, keyID)

	// Save private key
	privatePath := filepath.Join(outputDir, fmt.Sprintf(privateKeyFileNameFormat, domain))
	if err := pintcrypto.SaveEd25519PrivateKeyToFile(privateKey, keyID, privatePath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("✓ Private JWK: %s (kid: %s)\n", privatePath, keyID)

	return nil
}

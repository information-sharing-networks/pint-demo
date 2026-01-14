// keygen is a CLI tool for creating JWK sets for PINT platforms.
//
// Generates key pairs in both JWK and PEM formats:
// - JWK format for PINT message signing (private) and publishing (public)
// - PEM format for creating Certificate Signing Requests (CSR) to send to a CA - PEMS are in PKCS#8 format
//
// Workflow:
// 1. Generate keys with keygen → JWK files (for PINT) + PEM file (for CSR)
// 2. Create CSR using the PEM key
// 3. Send CSR to CA → receive signed certificate
// 4. Publish public JWK at https://domain/.well-known/jwks.json
// 5. Use private JWK for signing PINT messages
//
// the publick key PEM file is not strictly necessary, but it's useful for testing.

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

// file naming convention
const (
	publicKeyFileNameFormat     = "%s.public.jwk"
	privateKeyFileNameFormat    = "%s.private.jwk"
	privatePemKeyFileNameFormat = "%s.private.pem"
	publicPemKeyFileNameFormat  = "%s.public.pem"
)

var (
	hostname  string
	outputDir string
	kid       string
	keyType   string
	rsaSize   int
)

func main() {
	rootCmd := &cobra.Command{
		Use:               "keygen",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		Short:             "Create JWK sets for PINT platforms",
		Long: `Create JWK (JSON Web Key) sets for PINT platforms.

Generates key pairs in both JWK and PEM formats

Example:
  keygen --type ed25519 --hostname eblplatform.example.com --outputdir ./keys

Outputs:
  eblplatform.example.com.private.jwk  (for signing PINT messages)
  eblplatform.example.com.public.jwk   (publish at https://eblplatform.example.com/.well-known/jwks.json)
  eblplatform.example.com.private.pem  (for creating CSR to send to CA)
  
  never share the private key files. 
  `,
		RunE: run,
	}

	v := version.Get()
	rootCmd.Version = fmt.Sprintf("%s (built %s, commit %s)", v.Version, v.BuildDate, v.GitCommit)

	// Common flags
	rootCmd.Flags().StringVarP(&hostname, "hostname", "d", "", "Hostname (e.g., example.com)")
	rootCmd.Flags().StringVarP(&outputDir, "outputdir", "o", "", "Output directory for generated JWK [required]")
	rootCmd.Flags().StringVarP(&kid, "kid", "k", "", "Key ID (default: auto-generated from JWK thumbprint)")

	// Flags
	rootCmd.Flags().StringVarP(&keyType, "type", "t", "", "Key type: rsa or ed25519 [required]")
	rootCmd.Flags().IntVarP(&rsaSize, "size", "s", 4096, "RSA key size in bits: 2048 or 4096 (default: 4096)")

	// Required flags
	if err := rootCmd.MarkFlagRequired("outputdir"); err != nil {
		panic(err)
	}
	if err := rootCmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}
	if err := rootCmd.MarkFlagRequired("hostname"); err != nil {
		panic(err)
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Validate flags
	if keyType != "rsa" && keyType != "ed25519" {
		return fmt.Errorf("invalid key type: %s (must be 'rsa' or 'ed25519')", keyType)
	}

	if keyType == "rsa" && rsaSize != 2048 && rsaSize != 4096 {
		return fmt.Errorf("invalid RSA key size: %d (must be 2048 or 4096)", rsaSize)
	}

	// Create output directory if it doesn't exist
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outputDir, 0750); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if keyType == "rsa" {
		return generateRSAKeys()
	}
	return generateEd25519Keys()
}

func generateRSAKeys() error {
	fmt.Printf("Generating %d-bit RSA key pair for domain: %s\n", rsaSize, hostname)

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

	// Save public JWK
	publicFilename := fmt.Sprintf(publicKeyFileNameFormat, hostname)
	publicPath := filepath.Join(outputDir, publicFilename)
	if err := pintcrypto.SaveRSAPublicKeyToJWKFile(&privateKey.PublicKey, keyID, publicPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	fmt.Printf("✓ Public JWK:  %s (kid: %s)\n", publicPath, keyID)

	// Save private JWK
	privateFilename := fmt.Sprintf(privateKeyFileNameFormat, hostname)
	privatePath := filepath.Join(outputDir, privateFilename)
	if err := pintcrypto.SaveRSAPrivateKeyToJWKFile(privateKey, keyID, privatePath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("✓ Private JWK: %s (kid: %s)\n", privatePath, keyID)

	// Save private key in PEM format (for CSR generation)
	privatePemFilename := fmt.Sprintf(privatePemKeyFileNameFormat, hostname)
	privatePemPath := filepath.Join(outputDir, privatePemFilename)
	if err := pintcrypto.SaveRSAPrivateKeyToPEMFile(privateKey, privatePemPath); err != nil {
		return fmt.Errorf("failed to save PEM key: %w", err)
	}
	fmt.Printf("✓ Private PEM: %s (for CSR/certificate generation)\n", privatePemPath)

	// Save public key in PEM format (for testing)
	publicPemFilename := fmt.Sprintf(publicPemKeyFileNameFormat, hostname)
	publicPemPath := filepath.Join(outputDir, publicPemFilename)
	if err := pintcrypto.SaveRSAPublicKeyToPEMFile(&privateKey.PublicKey, publicPemPath); err != nil {
		return fmt.Errorf("failed to save PEM key: %w", err)
	}
	fmt.Printf("✓ Public PEM:  %s (for testing)\n", publicPemPath)

	return nil
}

func generateEd25519Keys() error {
	fmt.Printf("Generating Ed25519 key pair for domain: %s\n", hostname)

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

	// Save public JWK
	publicFilename := fmt.Sprintf(publicKeyFileNameFormat, hostname)
	publicPath := filepath.Join(outputDir, publicFilename)
	if err := pintcrypto.SaveEd25519PublicKeyToJWKFile(publicKey, keyID, publicPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	fmt.Printf("✓ Public JWK:  %s (kid: %s)\n", publicPath, keyID)

	// Save private JWK
	privateFilename := fmt.Sprintf(privateKeyFileNameFormat, hostname)
	privatePath := filepath.Join(outputDir, privateFilename)
	if err := pintcrypto.SaveEd25519PrivateKeyToJWKFile(privateKey, keyID, privatePath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("✓ Private JWK: %s (kid: %s)\n", privatePath, keyID)

	// Save private key in PEM format (for CSR generation)
	privatePemFilename := fmt.Sprintf(privatePemKeyFileNameFormat, hostname)
	privatePemPath := filepath.Join(outputDir, privatePemFilename)
	if err := pintcrypto.SaveEd25519PrivateKeyToPEMFile(privateKey, privatePemPath); err != nil {
		return fmt.Errorf("failed to save PEM key: %w", err)
	}
	fmt.Printf("✓ Private PEM: %s (for CSR/certificate generation)\n", privatePemPath)

	// Save public key in PEM format (for testing)
	publicPemFilename := fmt.Sprintf(publicPemKeyFileNameFormat, hostname)
	publicPemPath := filepath.Join(outputDir, publicPemFilename)
	if err := pintcrypto.SaveEd25519PublicKeyToPEMFile(publicKey, publicPemPath); err != nil {
		return fmt.Errorf("failed to save PEM key: %w", err)
	}
	fmt.Printf("✓ Public PEM:  %s (for testing)\n", publicPemPath)

	return nil
}

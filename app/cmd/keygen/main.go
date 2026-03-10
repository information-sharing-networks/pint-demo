package main

// keygen is a CLI tool for creating JWK sets for PINT platforms.
//
// Generates key pairs in both JWK and PEM formats:
// - JWK format for PINT message signing (private) and publishing (public)
// - PEM format for creating Certificate Signing Requests (CSR) to send to a CA - PEMS are in PKCS#8 format
//
// The key ID (kid) is generated as a SHA256 thumbprint of the public key in JWK format (RFC7638)
// You can specify the length of the kid using the -l flag (default is 16 chars = 8 bytes)
// (specify 0 or 64 for full length)
//
// Workflow:
// 1. Generate keys with keygen → JWK files (for PINT) + PEM file (for CSR)
// 2. Create CSR using the PEM key
// 3. Send CSR to CA → receive signed certificate
// 4. Publish public JWK at https://domain/.well-known/jwks.json
// 5. Use private JWK for signing PINT messages
//
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
	hostname      string
	outputDir     string
	kid           string
	keyType       string
	rsaSize       int
	kidLength     int
	publicJWKDir  string
	privateJWKDir string
	pemDir        string
)

func main() {
	rootCmd := &cobra.Command{
		Use:               "keygen",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		Short:             "Create JWK sets for PINT platforms",
		Long: `Create JWK (JSON Web Key) sets for PINT platforms.

Generates key pairs in both JWK and PEM formats

Example:
  keygen --type ed25519 --hostname eblplatform.example.com -l 16 --outputdir ./keys

Outputs:
  private/eblplatform.example.com.private.jwk  (for signing PINT messages)
  public/eblplatform.example.com.public.jwk   (publish at https://eblplatform.example.com/.well-known/jwks.json)
  pem/eblplatform.example.com.private.pem  (for creating CSR to send to CA)
  pem/eblplatform.example.com.public.pem  (for testing)
  
  never share the private key files. 

  The key ID (kid) is generated as a SHA256 thumbprint of the public key (RFC7638)
  You can specify the length of the kid using the -l flag (default is 16 chars)
  (specify 0 for full length)
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
	rootCmd.Flags().IntVarP(&kidLength, "kidlength", "l", 16, "Key ID length in chars (default: 16, 0 for full length)")

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

	if kidLength < 0 || kidLength > 64 {
		return fmt.Errorf("invalid kid length: %d (must be between 0 and 64)", kidLength)
	}

	// subdir paths
	publicJWKDir = filepath.Join(outputDir, "public")
	privateJWKDir = filepath.Join(outputDir, "private")
	pemDir = filepath.Join(outputDir, "pem")

	// Create output directory if it doesn't exist
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outputDir, 0750); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Create subdirs
	subdirs := []string{privateJWKDir, publicJWKDir, pemDir}
	for _, subdir := range subdirs {
		if _, err := os.Stat(subdir); os.IsNotExist(err) {
			if err := os.MkdirAll(subdir, 0750); err != nil {
				return fmt.Errorf("failed to create output subdirectory %s: %w", subdir, err)
			}
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

	// Save public JWK (kid is auto-generated from thumbprint)
	publicFilename := fmt.Sprintf(publicKeyFileNameFormat, hostname)
	publicJWKPath := filepath.Join(publicJWKDir, publicFilename)
	if err := pintcrypto.SaveRSAPublicKeyToJWKFile(&privateKey.PublicKey, publicJWKPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// Get the auto-generated kid for display
	keyID, err := pintcrypto.GenerateDefaultKeyID(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to generate key ID: %w", err)
	}
	fmt.Printf("✓ Public JWK:  %s (kid: %s)\n", publicJWKPath, keyID)

	// Save private JWK (kid is auto-generated from thumbprint)
	privateFilename := fmt.Sprintf(privateKeyFileNameFormat, hostname)
	privateJWKPath := filepath.Join(privateJWKDir, privateFilename)
	if err := pintcrypto.SaveRSAPrivateKeyToJWKFile(privateKey, privateJWKPath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("✓ Private JWK: %s (kid: %s)\n", privateJWKPath, keyID)

	// Save private key in PEM format (for CSR generation)
	privatePemFilename := fmt.Sprintf(privatePemKeyFileNameFormat, hostname)
	privatePemPath := filepath.Join(pemDir, privatePemFilename)
	if err := pintcrypto.SaveRSAPrivateKeyToPEMFile(privateKey, privatePemPath); err != nil {
		return fmt.Errorf("failed to save PEM key: %w", err)
	}
	fmt.Printf("✓ Private PEM: %s (for CSR/certificate generation)\n", privatePemPath)

	// Save public key in PEM format (for testing)
	publicPemFilename := fmt.Sprintf(publicPemKeyFileNameFormat, hostname)
	publicPemPath := filepath.Join(pemDir, publicPemFilename)
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

	// Save public JWK (kid is auto-generated from thumbprint)
	publicFilename := fmt.Sprintf(publicKeyFileNameFormat, hostname)
	publicJWKPath := filepath.Join(publicJWKDir, publicFilename)
	if err := pintcrypto.SaveEd25519PublicKeyToJWKFile(publicKey, publicJWKPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// Get the auto-generated kid for display
	keyID, err := pintcrypto.GenerateDefaultKeyID(publicKey)
	if err != nil {
		return fmt.Errorf("failed to generate key ID: %w", err)
	}
	fmt.Printf("✓ Public JWK:  %s (kid: %s)\n", publicJWKPath, keyID)

	// Save private JWK (kid is auto-generated from thumbprint)
	privateFilename := fmt.Sprintf(privateKeyFileNameFormat, hostname)
	privateJWKPath := filepath.Join(privateJWKDir, privateFilename)
	if err := pintcrypto.SaveEd25519PrivateKeyToJWKFile(privateKey, privateJWKPath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("✓ Private JWK: %s (kid: %s)\n", privateJWKPath, keyID)

	// Save private key in PEM format (for CSR generation)
	privatePemFilename := fmt.Sprintf(privatePemKeyFileNameFormat, hostname)
	privatePemPath := filepath.Join(pemDir, privatePemFilename)
	if err := pintcrypto.SaveEd25519PrivateKeyToPEMFile(privateKey, privatePemPath); err != nil {
		return fmt.Errorf("failed to save PEM key: %w", err)
	}
	fmt.Printf("✓ Private PEM: %s (for CSR/certificate generation)\n", privatePemPath)

	// Save public key in PEM format (for testing)
	publicPemFilename := fmt.Sprintf(publicPemKeyFileNameFormat, hostname)
	publicPemPath := filepath.Join(pemDir, publicPemFilename)
	if err := pintcrypto.SaveEd25519PublicKeyToPEMFile(publicKey, publicPemPath); err != nil {
		return fmt.Errorf("failed to save PEM key: %w", err)
	}
	fmt.Printf("✓ Public PEM:  %s (for testing)\n", publicPemPath)

	return nil
}

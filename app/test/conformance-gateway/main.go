package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "keys-from-pem",
		Short: "Create pint keys from private key PEM files",
		Long: `Create public JWK files from private key PEM files for use in testing.

Usage: keys-from-pem -p <private-key-pem-file> -o <output-dir> -s <server-name>

... creates <output-dir>/<server-name>.public.jwk and outputs the kid
				
				`,
	}
	cmd.Flags().StringP("private-key-pem", "p", "", "Path to private key PEM file")
	cmd.Flags().StringP("output-dir", "o", "", "Output directory for public key JWK file")
	cmd.Flags().StringP("server-name", "s", "", "Server name")
	cmd.MarkFlagRequired("private-key-pem")
	cmd.MarkFlagRequired("output-dir")

	cmd.Run = func(cmd *cobra.Command, args []string) {
		privateKeyPEM, _ := cmd.Flags().GetString("private-key-pem")
		outputDir, _ := cmd.Flags().GetString("output-dir")
		serverName, _ := cmd.Flags().GetString("server-name")
		filename := fmt.Sprintf("%s/%s.public.jwk", outputDir, serverName)

		// open the private key PEM file
		pemData, err := os.ReadFile(privateKeyPEM)
		if err != nil {
			fmt.Printf("Error reading private key PEM file: %v\n", err)
			os.Exit(1)
		}

		// Load private key (RSA or Ed25519 keys)
		privateKey, err := parsePrivateKey(pemData)
		if err != nil {
			fmt.Printf("Error parsing private key: %v\n", err)
			os.Exit(1)
		}

		kid := ""
		switch pk := privateKey.(type) {
		case *rsa.PrivateKey:
			publicKey := &pk.PublicKey
			if err := crypto.SaveRSAPublicKeyToJWKFile(publicKey, filename); err != nil {
				fmt.Printf("Error saving public key: %v\n", err)
				os.Exit(1)
			}
			kid, err = crypto.GenerateKeyIDFromRSAKey(publicKey)
			if err != nil {
				fmt.Printf("Error generating key ID: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("RSA public key saved to %s\n", filename)
			fmt.Printf("  kid:      %s\n", kid)
		case ed25519.PrivateKey:
			publicKey := pk.Public().(ed25519.PublicKey)
			filename := fmt.Sprintf("%s/public.jwk", outputDir)
			fmt.Printf("Saving Ed25519 public key to %s\n", filename)
			if err := crypto.SaveEd25519PublicKeyToJWKFile(publicKey, filename); err != nil {
				fmt.Printf("Error saving public key: %v\n", err)
				os.Exit(1)
			}
			kid, err = crypto.GenerateKeyIDFromEd25519Key(publicKey)
			if err != nil {
				fmt.Printf("Error generating key ID: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Ed25519 public key saved to %s\n", filename)
			fmt.Printf("  kid:      %s\n", kid)
		default:
			fmt.Printf("Unsupported key type: %T\n", privateKey)
			os.Exit(1)
		}

	}
	// run the command
	cmd.Execute()
}

func parsePrivateKey(pemData []byte) (any, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	// parse the private key using x509.ParsePKCS8PrivateKey
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case ed25519.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

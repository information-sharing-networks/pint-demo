// this file contains functions to generate and manage public/private key pairs
//
// Because participating parties in PINT exchanges may have different policies on acceptable key types,
// DSCA do not specify which algorithm should be used to generate public/private keys
//
// This implementation supports both ED25519 and RSA key types.
// ED25519 is the recommended key type since it is more secure and efficient than RSA.
// keys are saved in JWK format

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// GenerateEd25519KeyPair generates a new ED25519 private key
func GenerateEd25519KeyPair() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return privateKey, nil
}

// SaveEd25519PrivateKeyToFile saves an ED25519 private key to a JWK file
// note the key is not encrypted
func SaveEd25519PrivateKeyToFile(privateKey ed25519.PrivateKey, keyID, filepath string) error {
	jwkKey, err := Ed25519PrivateKeyToJWK(privateKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to create JWK: %w", err)
	}

	jwkSet := jwk.NewSet()
	jwkSet.AddKey(jwkKey)

	jsonBytes, err := json.MarshalIndent(jwkSet, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JWK set: %w", err)
	}

	if err := os.WriteFile(filepath, jsonBytes, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// SaveEd25519PublicKeyToFile saves an ED25519 public key to a JWK file
func SaveEd25519PublicKeyToFile(publicKey ed25519.PublicKey, keyID, filepath string) error {
	jwkKey, err := Ed25519PublicKeyToJWK(publicKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to create JWK: %w", err)
	}

	jwkSet := jwk.NewSet()
	jwkSet.AddKey(jwkKey)

	jsonBytes, err := json.MarshalIndent(jwkSet, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JWK set: %w", err)
	}

	if err := os.WriteFile(filepath, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ReadEd25519PrivateKeyFromFile loads an ED25519 private key from a JWK file
func ReadEd25519PrivateKeyFromFile(filepath string) (ed25519.PrivateKey, error) {
	jsonBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	jwkSet, err := jwk.Parse(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK set: %w", err)
	}

	if jwkSet.Len() == 0 {
		return nil, fmt.Errorf("JWK set is empty")
	}

	jwkKey, ok := jwkSet.Key(0)
	if !ok {
		return nil, fmt.Errorf("failed to get key from JWK set")
	}

	var raw any
	if err := jwk.Export(jwkKey, &raw); err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	privateKey, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 private key")
	}

	return privateKey, nil
}

// ReadEd25519PublicKeyFromFile loads an ed25519 public key from a JWK file
func ReadEd25519PublicKeyFromFile(filepath string) (ed25519.PublicKey, error) {
	jsonBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	jwkSet, err := jwk.Parse(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK set: %w", err)
	}

	if jwkSet.Len() == 0 {
		return nil, fmt.Errorf("JWK set is empty")
	}

	jwkKey, ok := jwkSet.Key(0)
	if !ok {
		return nil, fmt.Errorf("failed to get key from JWK set")
	}

	var raw any
	if err := jwk.Export(jwkKey, &raw); err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	publicKey, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 public key")
	}

	return publicKey, nil
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit size
// minimum key size is 2048 bits (4096 is recommended) - key size must be a multiple of 256
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("key size must be at least 2048 bits")
	}

	if bits%256 != 0 {
		return nil, fmt.Errorf("key size should be a multiple of 256")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return privateKey, nil
}

// SaveRSAPrivateKeyToFile saves an RSA private key to a JWK file
func SaveRSAPrivateKeyToFile(privateKey *rsa.PrivateKey, keyID, filepath string) error {
	jwkKey, err := RSAPrivateKeyToJWK(privateKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to create JWK: %w", err)
	}

	jwkSet := jwk.NewSet()
	jwkSet.AddKey(jwkKey)

	jsonBytes, err := json.MarshalIndent(jwkSet, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JWK set: %w", err)
	}

	if err := os.WriteFile(filepath, jsonBytes, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// SaveRSAPublicKeyToFile saves an RSA public key to a JWK file
func SaveRSAPublicKeyToFile(publicKey *rsa.PublicKey, keyID, filepath string) error {
	jwkKey, err := RSAPublicKeyToJWK(publicKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to create JWK: %w", err)
	}

	jwkSet := jwk.NewSet()
	jwkSet.AddKey(jwkKey)

	jsonBytes, err := json.MarshalIndent(jwkSet, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JWK set: %w", err)
	}

	if err := os.WriteFile(filepath, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ReadRSAPrivateKeyFromFile loads an RSA private key from a JWK file
func ReadRSAPrivateKeyFromFile(filepath string) (*rsa.PrivateKey, error) {
	jsonBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	jwkSet, err := jwk.Parse(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK set: %w", err)
	}

	if jwkSet.Len() == 0 {
		return nil, fmt.Errorf("JWK set is empty")
	}

	jwkKey, ok := jwkSet.Key(0)
	if !ok {
		return nil, fmt.Errorf("failed to get key from JWK set")
	}

	var raw any
	if err := jwk.Export(jwkKey, &raw); err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	privateKey, ok := raw.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}

	return privateKey, nil
}

// ReadRSAPublicKeyFromFile loads an RSA public key from a JWK file
func ReadRSAPublicKeyFromFile(filepath string) (*rsa.PublicKey, error) {
	jsonBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	jwkSet, err := jwk.Parse(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK set: %w", err)
	}

	if jwkSet.Len() == 0 {
		return nil, fmt.Errorf("JWK set is empty")
	}

	jwkKey, ok := jwkSet.Key(0)
	if !ok {
		return nil, fmt.Errorf("failed to get key from JWK set")
	}

	var raw any
	if err := jwk.Export(jwkKey, &raw); err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	publicKey, ok := raw.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return publicKey, nil
}

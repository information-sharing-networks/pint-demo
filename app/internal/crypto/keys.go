// this file contains functions to generate and manage public/private key pairs
//
// Because participating parties in PINT exchanges may have different policies on acceptable key types,
// DSCA do not specify which algorithm should be used to generate public/private keys
//
// This implementation supports both ED25519 and RSA key types.
// ED25519 is the recommended key type since it is more secure and efficient than RSA.

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateEd25519KeyPair generates a new ED25519 private key
func GenerateEd25519KeyPair() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return privateKey, nil
}

// SaveEd25519PrivateKeyToFile saves an ED25519 private key to a PEM file
// note the key is not encrypted
func SaveEd25519PrivateKeyToFile(privateKey ed25519.PrivateKey, filepath string) error {

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	return nil
}

// SaveEd25519PublicKeyToFile saves an ED25519 public key to a PEM file
func SaveEd25519PublicKeyToFile(publicKey ed25519.PublicKey, filepath string) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to write public key to file: %w", err)
	}

	return nil
}

// ReadEd25519PrivateKeyFromFile loads an ED25519 private key from a PEM file
func ReadEd25519PrivateKeyFromFile(filepath string) (ed25519.PrivateKey, error) {

	pemBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to find or decode PRIVATE KEY PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ed25519 key")
	}

	return ed25519PrivateKey, nil
}

// ReadEd25519PublicKeyFromFile loads an ed25519 public key from a PEM file
func ReadEd25519PublicKeyFromFile(filepath string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to find or decode PUBLIC KEY PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519PublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ed25519 key")
	}

	return ed25519PublicKey, nil
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

// SaveRSAPrivateKeyToFile saves an RSA private key to a PEM file
func SaveRSAPrivateKeyToFile(privateKey *rsa.PrivateKey, filepath string) error {

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	if err := pem.Encode(file, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}
	return nil
}

// SaveRSAPublicKeyToFile saves an RSA public key to a PEM file
func SaveRSAPublicKeyToFile(publicKey *rsa.PublicKey, filepath string) error {

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	if err := pem.Encode(file, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}
	return nil
}

// ReadRSAPrivateKeyFromFile loads an RSA private key from a PEM file
func ReadRSAPrivateKeyFromFile(filepath string) (*rsa.PrivateKey, error) {

	pemBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return rsaPrivateKey, nil
}

// ReadRSAPublicKeyFromFile loads an RSA public key from a PEM file
func ReadRSAPublicKeyFromFile(filepath string) (*rsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key")
	}

	return rsaPublicKey, nil
}

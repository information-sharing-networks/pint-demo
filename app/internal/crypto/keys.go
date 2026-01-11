// this file contains functions to generate and manage public/private key pairs
//
// Because participating parties in PINT exchanges may have different policies on acceptable key types,
// DSCA do not specify which algorithm should be used to generate public/private keys
//
// This implementation supports both ED25519 and RSA key types.
// ED25519 is the recommended key type since it is more secure and efficient than RSA.
// keys are saved in JWK format
//
// PEM files are in PKCS#8 format (https://datatracker.ietf.org/doc/html/rfc5208)

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

// SaveEd25519PrivateKeyToJWKFile saves an ED25519 private key to a JWK file
// note the key is not encrypted
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.jwk")
func SaveEd25519PrivateKeyToJWKFile(privateKey ed25519.PrivateKey, keyID, baseDir, filename string) error {
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

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	if err := root.WriteFile(filename, jsonBytes, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// SaveEd25519PublicKeyToJWKFile saves an ED25519 public key to a JWK file
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.jwk")
func SaveEd25519PublicKeyToJWKFile(publicKey ed25519.PublicKey, keyID, baseDir, filename string) error {
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

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	if err := root.WriteFile(filename, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// SaveEd25519PrivateKeyToPEMFile saves an Ed25519 private key to a PEM file in PKCS#8 format
// the app uses JWK for key exchange - this function is primarily for generating a PEM file for creating a CSR
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.pem")
func SaveEd25519PrivateKeyToPEMFile(privateKey ed25519.PrivateKey, baseDir, filename string) error {
	// Marshal to PKCS#8 format
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	file, err := root.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}

	return nil
}

// SaveEd25519PublicKeyToPEMFile saves an Ed25519 public key to a PEM file in SubjectPublicKeyInfo format
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.pem")
func SaveEd25519PublicKeyToPEMFile(publicKey ed25519.PublicKey, baseDir, filename string) error {
	// Marshal to SubjectPublicKeyInfo format
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	file, err := root.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}

	return nil
}

// ReadEd25519PrivateKeyFromJWKFile loads an ED25519 private key from a JWK file
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.jwk")
func ReadEd25519PrivateKeyFromJWKFile(baseDir, filename string) (ed25519.PrivateKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	jsonBytes, err := root.ReadFile(filename)
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

// ReadEd25519PublicKeyFromJWKFile loads an ed25519 public key from a JWK file
//
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.jwk")
func ReadEd25519PublicKeyFromJWKFile(baseDir, filename string) (ed25519.PublicKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	jsonBytes, err := root.ReadFile(filename)
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

// ReadEd25519PrivateKeyFromPEMFile loads an Ed25519 private key from a PEM file in PKCS#8 format
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.pem")
func ReadEd25519PrivateKeyFromPEMFile(baseDir, filename string) (ed25519.PrivateKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	pemData, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block is not a private key (type: %s)", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 private key")
	}

	return privateKey, nil
}

// ReadEd25519PublicKeyFromPEMFile loads an Ed25519 public key from a PEM file in SubjectPublicKeyInfo format
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.pem")
func ReadEd25519PublicKeyFromPEMFile(baseDir, filename string) (ed25519.PublicKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	pemData, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block is not a public key (type: %s)", block.Type)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pubKey.(ed25519.PublicKey)
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

// SaveRSAPrivateKeyToJWKFile saves an RSA private key to a JWK file
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.jwk")
func SaveRSAPrivateKeyToJWKFile(privateKey *rsa.PrivateKey, keyID, baseDir, filename string) error {
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

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	if err := root.WriteFile(filename, jsonBytes, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// SaveRSAPublicKeyToJWKFile saves an RSA public key to a JWK file
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.jwk")
func SaveRSAPublicKeyToJWKFile(publicKey *rsa.PublicKey, keyID, baseDir, filename string) error {
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

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	if err := root.WriteFile(filename, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// SaveRSAPrivateKeyToPEMFile saves an RSA private key to a PEM file in PKCS#8 format
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.pem")
func SaveRSAPrivateKeyToPEMFile(privateKey *rsa.PrivateKey, baseDir, filename string) error {
	// Marshal to PKCS#8 format (more modern than PKCS#1)
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	file, err := root.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}

	return nil
}

// SaveRSAPublicKeyToPEMFile saves an RSA public key to a PEM file in SubjectPublicKeyInfo format
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.pem")
func SaveRSAPublicKeyToPEMFile(publicKey *rsa.PublicKey, baseDir, filename string) error {
	// Marshal to SubjectPublicKeyInfo format
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	file, err := root.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}

	return nil
}

// ReadRSAPrivateKeyFromJWKFile loads an RSA private key from a JWK file
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.jwk")
func ReadRSAPrivateKeyFromJWKFile(baseDir, filename string) (*rsa.PrivateKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	jsonBytes, err := root.ReadFile(filename)
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

// ReadRSAPublicKeyFromJWKFile loads an RSA public key from a JWK file
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.jwk")
func ReadRSAPublicKeyFromJWKFile(baseDir, filename string) (*rsa.PublicKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	jsonBytes, err := root.ReadFile(filename)
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

// ReadRSAPrivateKeyFromPEMFile loads an RSA private key from a PEM file in PKCS#8 format
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "private.pem")
func ReadRSAPrivateKeyFromPEMFile(baseDir, filename string) (*rsa.PrivateKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	pemData, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block is not a private key (type: %s)", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}

	return privateKey, nil
}

// ReadRSAPublicKeyFromPEMFile loads an RSA public key from a PEM file in SubjectPublicKeyInfo format
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./keys")
//   - filename: The filename within the base directory (e.g., "public.pem")
func ReadRSAPublicKeyFromPEMFile(baseDir, filename string) (*rsa.PublicKey, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	pemData, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block is not a public key (type: %s)", block.Type)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return publicKey, nil
}

// ReadCertificateFromPEMFile reads a single X.509 certificate from a PEM file.
// If the file contains multiple certificates, only the first one is returned (this will be the leaf cert).
//
// Parameters:
//   - baseDir: The base directory to scope file access (e.g., "./certs")
//   - filename: The filename within the base directory (e.g., "cert.pem")
func ReadCertificateFromPEMFile(baseDir, filename string) (*x509.Certificate, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory %s: %w", baseDir, err)
	}
	defer root.Close()

	pemData, err := root.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate (type: %s)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

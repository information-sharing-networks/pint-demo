// JWK (JSON Web Key) Implementation for DCSA PINT
//
// these functions convert raw RSA/Ed25519 public keys to JWK format (and vice versa)
// Reference: https://datatracker.ietf.org/doc/html/rfc7517 (JSON Web Key standard)
//
// these functions are used by keymanager.go to convert JWKs to native crypto types for signature verification
// ... and by keygen CLI to generate JWKs for distribution via /.well-known/jwks.json
// keygen also uses the PEM functions below to create a PEM file that can be used to create a CA CSR (certificate signing request)).
//

package crypto

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RSAPublicKeyToJWK converts a RSA public key to JWK format
func RSAPublicKeyToJWK(publicKey *rsa.PublicKey, keyID string) (jwk.Key, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}

	// create the jwk key
	key, err := jwk.Import(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from RSA public key: %w", err)
	}

	// Set key ID
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Set key usage
	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("failed to set key usage: %w", err)
	}

	return key, nil
}

// RSAPrivateKeyToJWK converts an RSA private key to JWK format
func RSAPrivateKeyToJWK(privateKey *rsa.PrivateKey, keyID string) (jwk.Key, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from RSA private key: %w", err)
	}

	// Set key ID
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Set key usage
	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("failed to set key usage: %w", err)
	}

	return key, nil
}

// Ed25519PublicKeyToJWK converts an Ed25519 public key to JWK format
func Ed25519PublicKeyToJWK(publicKey ed25519.PublicKey, keyID string) (jwk.Key, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}

	// Create JWK
	key, err := jwk.Import(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from Ed25519 public key: %w", err)
	}

	// Set key ID
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Set key usage
	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("failed to set key usage: %w", err)
	}

	return key, nil
}

// Ed25519PrivateKeyToJWK converts an Ed25519 private key to JWK format
func Ed25519PrivateKeyToJWK(privateKey ed25519.PrivateKey, keyID string) (jwk.Key, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}

	// Import the private key
	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from Ed25519 private key: %w", err)
	}

	// Set key ID
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Set key usage
	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("failed to set key usage: %w", err)
	}

	return key, nil
}

// JWKToRSAPublicKey converts a JWK to an RSA public key using lestrrat-go/jwx
func JWKToRSAPublicKey(key jwk.Key) (*rsa.PublicKey, error) {
	if key == nil {
		return nil, fmt.Errorf("key is nil")
	}

	var raw any
	// Export to raw key
	if err := jwk.Export(key, &raw); err != nil {
		return nil, fmt.Errorf("failed to export RSA public key: %w", err)
	}

	rsaPublicKey, ok := raw.(*rsa.PublicKey)
	if !ok {
		alg, _ := key.Algorithm()
		return nil, fmt.Errorf("expected RSA public key but got key with algorithm %v and type %T", alg, raw)
	}

	return rsaPublicKey, nil
}

// Ed25519JWKToPublicKey converts an Ed25519 JWK to an Ed25519 public key
func Ed25519JWKToPublicKey(key jwk.Key) (ed25519.PublicKey, error) {
	if key == nil {
		return nil, fmt.Errorf("jwk is nil")
	}

	var raw any
	// Export to raw key
	if err := jwk.Export(key, &raw); err != nil {
		return nil, fmt.Errorf("failed to export Ed25519 public key: %w", err)
	}

	ed25519PublicKey, ok := raw.(ed25519.PublicKey)
	if !ok {
		alg, _ := key.Algorithm()
		return nil, fmt.Errorf("expected Ed25519 public key but got key with algorithm %v and type %T", alg, raw)
	}

	return ed25519PublicKey, nil

}

// FetchJWKSet fetches a JWK set from a URL
func FetchJWKSet(ctx context.Context, url string) (jwk.Set, error) {
	// Fetch the JWK set
	set, err := jwk.Fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK set: %w", err)
	}

	return set, nil
}

// GenerateKeyIDFromRSAKey generates a key ID from an RSA private key using SHA-256 thumbprint.
// Returns the first 16 characters of the hex-encoded thumbprint.
// This is the recommended approach for generating key IDs for PINT per DCSA guidance.
func GenerateKeyIDFromRSAKey(publickey *rsa.PublicKey) (string, error) {
	if publickey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	// Import to JWK to calculate thumbprint
	jwkKey, err := jwk.Import(publickey)
	if err != nil {
		return "", fmt.Errorf("failed to import key: %w", err)
	}

	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to generate thumbprint: %w", err)
	}

	return fmt.Sprintf("%x", thumbprint)[:16], nil
}

// GenerateKeyIDFromEd25519Key generates a key ID from an Ed25519 private key using SHA-256 thumbprint.
// Returns the first 16 characters of the hex-encoded thumbprint (RFC 7638)
// This is the recommended approach for generating key IDs for PINT per DCSA guidance.
func GenerateKeyIDFromEd25519Key(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key length")
	}
	// Import to JWK to calculate thumbprint
	jwkKey, err := jwk.Import(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to import key: %w", err)
	}

	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to generate thumbprint: %w", err)
	}

	return fmt.Sprintf("%x", thumbprint)[:16], nil
}

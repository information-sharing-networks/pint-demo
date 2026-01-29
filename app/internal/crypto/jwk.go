package crypto

// JWK (JSON Web Key) Implementation for DCSA PINT
// Reference: https://datatracker.ietf.org/doc/html/rfc7517 (JSON Web Key standard)
//
// These functions are used by keymanager.go to convert JWKs to native crypto types for signature verification
// ... and by keygen CLI to generate JWKs for distribution via /.well-known/jwks.json
// keygen also uses the PEM functions below to create a PEM file that can be used to create a CA CSR (certificate signing request)).
//
// Note the JWK kid is generated using the first 16 characters (8 bytes) of the SHA-256 thumbprint of the public key.
//
// these are low level functions - for standard usage (issuance requests, transfer requests etc) you will not need to call these functions directly.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RSAPublicKeyToJWK converts a RSA public key to JWK format with auto-generated kid.
func RSAPublicKeyToJWK(publicKey *rsa.PublicKey) (jwk.Key, error) {
	if publicKey == nil {
		return nil, NewInternalError("public key is nil")
	}

	keyID, err := GenerateKeyIDFromRSAKey(publicKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to generate key ID")
	}

	key, err := jwk.Import(publicKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to create JWK from RSA public key")
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key ID")
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set algorithm")
	}

	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key usage")
	}

	return key, nil
}

// RSAPrivateKeyToJWK converts an RSA private key to JWK format with auto-generated kid.
func RSAPrivateKeyToJWK(privateKey *rsa.PrivateKey) (jwk.Key, error) {
	if privateKey == nil {
		return nil, NewInternalError("private key is nil")
	}

	keyID, err := GenerateKeyIDFromRSAKey(&privateKey.PublicKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to generate key ID")
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to create JWK from RSA private key")
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key ID")
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set algorithm")
	}

	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key usage")
	}

	return key, nil
}

// Ed25519PublicKeyToJWK converts an Ed25519 public key to JWK format with auto-generated kid.
func Ed25519PublicKeyToJWK(publicKey ed25519.PublicKey) (jwk.Key, error) {
	if publicKey == nil {
		return nil, NewInternalError("public key is nil")
	}

	keyID, err := GenerateKeyIDFromEd25519Key(publicKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to generate key ID")
	}

	key, err := jwk.Import(publicKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to create JWK from Ed25519 public key")
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key ID")
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set algorithm")
	}

	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key usage")
	}

	return key, nil
}

// Ed25519PrivateKeyToJWK converts an Ed25519 private key to JWK format with auto-generated kid.
func Ed25519PrivateKeyToJWK(privateKey ed25519.PrivateKey) (jwk.Key, error) {
	if privateKey == nil {
		return nil, NewInternalError("private key is nil")
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := GenerateKeyIDFromEd25519Key(publicKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to generate key ID")
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, WrapKeyManagementError(err, "failed to create JWK from Ed25519 private key")
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key ID")
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set algorithm")
	}

	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, WrapKeyManagementError(err, "failed to set key usage")
	}

	return key, nil
}

// JWKToRSAPublicKey converts a JWK to an RSA public key using lestrrat-go/jwx
func JWKToRSAPublicKey(key jwk.Key) (*rsa.PublicKey, error) {
	if key == nil {
		return nil, NewInternalError("key is nil")
	}

	var raw any
	// Export to raw key
	if err := jwk.Export(key, &raw); err != nil {
		return nil, WrapKeyManagementError(err, "failed to export RSA public key")
	}

	rsaPublicKey, ok := raw.(*rsa.PublicKey)
	if !ok {
		alg, _ := key.Algorithm()
		return nil, NewKeyManagementError(fmt.Sprintf("expected RSA public key but got key with algorithm %v and type %T", alg, raw))
	}

	return rsaPublicKey, nil
}

// Ed25519JWKToPublicKey converts an Ed25519 JWK to an Ed25519 public key
func Ed25519JWKToPublicKey(key jwk.Key) (ed25519.PublicKey, error) {
	if key == nil {
		return nil, NewInternalError("jwk is nil")
	}

	var raw any
	// Export to raw key
	if err := jwk.Export(key, &raw); err != nil {
		return nil, WrapKeyManagementError(err, "failed to export Ed25519 public key")
	}

	ed25519PublicKey, ok := raw.(ed25519.PublicKey)
	if !ok {
		alg, _ := key.Algorithm()
		return nil, NewKeyManagementError(fmt.Sprintf("expected Ed25519 public key but got key with algorithm %v and type %T", alg, raw))
	}

	return ed25519PublicKey, nil

}

// GenerateKeyIDFromRSAKey generates a key ID from an RSA private key using SHA-256 thumbprint.
// Returns the first 16 characters of the hex-encoded thumbprint.
//
// This is the recommended approach for generating key IDs for PINT
func GenerateKeyIDFromRSAKey(publickey *rsa.PublicKey) (string, error) {
	if publickey == nil {
		return "", NewInternalError("private key is nil")
	}

	// Import to JWK to calculate thumbprint
	jwkKey, err := jwk.Import(publickey)
	if err != nil {
		return "", WrapKeyManagementError(err, "failed to import key")
	}

	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", WrapKeyManagementError(err, "failed to generate thumbprint")
	}

	return fmt.Sprintf("%x", thumbprint)[:16], nil
}

// GenerateKeyIDFromEd25519Key generates a key ID from an Ed25519 private key using SHA-256 thumbprint.
// Returns the first 16 characters of the hex-encoded thumbprint (RFC 7638).
//
// This is the recommended approach for generating key IDs for PINT
func GenerateKeyIDFromEd25519Key(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", NewInternalError("invalid Ed25519 private key length")
	}
	// Import to JWK to calculate thumbprint
	jwkKey, err := jwk.Import(publicKey)
	if err != nil {
		return "", WrapKeyManagementError(err, "failed to import key")
	}

	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", WrapKeyManagementError(err, "failed to generate thumbprint")
	}

	return fmt.Sprintf("%x", thumbprint)[:16], nil
}

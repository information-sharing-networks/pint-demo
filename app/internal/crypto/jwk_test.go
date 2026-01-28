package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestRSAPublicKeyToJWK(t *testing.T) {

	// nil public key
	var publicKey *rsa.PublicKey
	_, err := RSAPublicKeyToJWK(publicKey)
	if err == nil {
		t.Fatalf("expected an error when passing nil public key, but got no error")
	}

	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Could not generate a RSA private Key %v", err)
	}

	key, err := RSAPublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("error converting RSA public key to JWK: %v", err)
	}

	// Test meta data is set correctly (keyID auto-generated, alg, usage)
	gotKeyID, ok := key.KeyID()
	if !ok {
		t.Fatalf("KeyID not set in JWK")
	}
	if gotKeyID == "" {
		t.Errorf("KeyID should be auto-generated, but got empty string")
	}

	alg, ok := key.Algorithm()
	if !ok {
		t.Fatalf("Algorithm not set in JWK")
	}
	expectedAlg := jwa.RS256()
	if alg.String() != expectedAlg.String() {
		t.Errorf("Algorithm mismatch: got %q, want %q", alg.String(), expectedAlg.String())
	}

	usage, ok := key.KeyUsage()
	if !ok {
		t.Fatalf("KeyUsage not set in JWK")
	}
	expectedUsage := jwk.ForSignature.String()
	if usage != expectedUsage {
		t.Errorf("KeyUsage mismatch: got %q, want %q", usage, expectedUsage)
	}
}

func TestEd25519PublicKeyToJWK(t *testing.T) {
	// nil public key
	var publicKey ed25519.PublicKey
	_, err := Ed25519PublicKeyToJWK(publicKey)
	if err == nil {
		t.Fatalf("expected an error when passing nil public key, but got no error")
	}

	// Generate Ed25519 key pair
	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Could not generate Ed25519 private key: %v", err)
	}
	publicKeyEd25519 := privateKey.Public().(ed25519.PublicKey)

	// Valid key
	key, err := Ed25519PublicKeyToJWK(publicKeyEd25519)
	if err != nil {
		t.Fatalf("error converting Ed25519 public key to JWK: %v", err)
	}

	// Test meta data is set correctly (keyID auto-generated, alg, usage)
	gotKeyID, ok := key.KeyID()
	if !ok {
		t.Fatalf("KeyID not set in JWK")
	}
	if gotKeyID == "" {
		t.Errorf("KeyID should be auto-generated, but got empty string")
	}

	// Test algorithm is set correctly
	alg, ok := key.Algorithm()
	if !ok {
		t.Fatalf("Algorithm not set in JWK")
	}
	expectedAlg := jwa.EdDSA()
	if alg.String() != expectedAlg.String() {
		t.Errorf("Algorithm mismatch: got %q, want %q", alg.String(), expectedAlg.String())
	}

	// Test key usage is set correctly
	usage, ok := key.KeyUsage()
	if !ok {
		t.Fatalf("KeyUsage not set in JWK")
	}
	expectedUsage := jwk.ForSignature.String()
	if usage != expectedUsage {
		t.Errorf("KeyUsage mismatch: got %q, want %q", usage, expectedUsage)
	}
}

func TestJWKToRSAPublicKey(t *testing.T) {
	// nil JWK
	var nilKey jwk.Key
	_, err := JWKToRSAPublicKey(nilKey)
	if err == nil {
		t.Fatalf("expected an error when passing nil JWK, but got no error")
	}

	// Generate RSA key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Could not generate RSA private key: %v", err)
	}
	originalPublicKey := &privateKey.PublicKey

	// Convert to JWK
	jwkKey, err := RSAPublicKeyToJWK(originalPublicKey)
	if err != nil {
		t.Fatalf("error converting RSA public key to JWK: %v", err)
	}

	// Convert back to RSA public key
	convertedPublicKey, err := JWKToRSAPublicKey(jwkKey)
	if err != nil {
		t.Fatalf("error converting JWK to RSA public key: %v", err)
	}

	// Verify the keys match
	if !originalPublicKey.Equal(convertedPublicKey) {
		t.Errorf("converted public key does not match original")
	}

	// Test with wrong key type (Ed25519)
	ed25519PrivateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Could not generate Ed25519 private key: %v", err)
	}
	ed25519PublicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)

	ed25519JWK, err := Ed25519PublicKeyToJWK(ed25519PublicKey)
	if err != nil {
		t.Fatalf("error converting Ed25519 public key to JWK: %v", err)
	}

	_, err = JWKToRSAPublicKey(ed25519JWK)
	if err == nil {
		t.Fatalf("expected an error when passing Ed25519 JWK to RSA converter, but got no error")
	}
}

func TestEd25519JWKToPublicKey(t *testing.T) {
	// nil JWK
	var nilKey jwk.Key
	_, err := Ed25519JWKToPublicKey(nilKey)
	if err == nil {
		t.Fatalf("expected an error when passing nil JWK, but got no error")
	}

	// Generate Ed25519 key pair
	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Could not generate Ed25519 private key: %v", err)
	}
	originalPublicKey := privateKey.Public().(ed25519.PublicKey)

	// Convert to JWK
	jwkKey, err := Ed25519PublicKeyToJWK(originalPublicKey)
	if err != nil {
		t.Fatalf("error converting Ed25519 public key to JWK: %v", err)
	}

	// Convert back to Ed25519 public key
	convertedPublicKey, err := Ed25519JWKToPublicKey(jwkKey)
	if err != nil {
		t.Fatalf("error converting JWK to Ed25519 public key: %v", err)
	}

	// Verify the keys match
	if !originalPublicKey.Equal(convertedPublicKey) {
		t.Errorf("converted public key does not match original")
	}

	// Test with wrong key type (RSA)
	rsaPrivateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Could not generate RSA private key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	rsaJWK, err := RSAPublicKeyToJWK(rsaPublicKey)
	if err != nil {
		t.Fatalf("error converting RSA public key to JWK: %v", err)
	}

	_, err = Ed25519JWKToPublicKey(rsaJWK)
	if err == nil {
		t.Fatalf("expected an error when passing RSA JWK to Ed25519 converter, but got no error")
	}
}

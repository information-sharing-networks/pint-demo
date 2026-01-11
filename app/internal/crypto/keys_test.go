package crypto

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// test that only valid RSA key sizes are accepted
func TestGenerateRSAKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{
			name:    "generate 2048-bit key",
			bits:    2048,
			wantErr: false,
		},
		{
			name:    "generate 4096-bit key",
			bits:    4096,
			wantErr: false,
		},
		{
			name:    "generate key with too small size",
			bits:    1024,
			wantErr: true,
		},
		{
			name:    "generate key with invalid size",
			bits:    2500,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := GenerateRSAKeyPair(tt.bits)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if privateKey.N.BitLen() != int(tt.bits) {
				t.Errorf("key bit length = %d, want %d", privateKey.N.BitLen(), tt.bits)
			}
		})
	}
}

// generate a Ed25519 key pair, save the private and public keys to JWK files, read them back and compare
func TestSaveAndReadEd25519JWK(t *testing.T) {
	// JWK private key
	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "private.jwk")

	keyID = "test_kid"

	if err := SaveEd25519PrivateKeyToJWKFile(privateKey, keyID, tmpDir, "private.jwk"); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}

	loadedPrivateKey, err := ReadEd25519PrivateKeyFromJWKFile(tmpDir, "private.jwk")
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	if !privateKey.Equal(loadedPrivateKey) {
		t.Error("loaded private key does not match original")
	}

	// Verify file permissions
	info, err := os.Stat(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to stat private key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("private key file permissions = %v, want 0600", info.Mode().Perm())
	}

	// public key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	if err := SaveEd25519PublicKeyToJWKFile(publicKey, keyID, tmpDir, "public.pem"); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	loadedPublicKey, err := ReadEd25519PublicKeyFromJWKFile(tmpDir, "public.pem")
	if err != nil {
		t.Fatalf("could not read public key from PEM file: %v", err)
	}

	if !publicKey.Equal(loadedPublicKey) {
		t.Errorf("loaded public key does not equal original public key")
	}

}

// generate a key pair, save the private and public keys to PEM files, read them back and compare
func TestSaveAndReadEd25519PEM(t *testing.T) {
	// Generate a key pair
	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tmpDir := t.TempDir()
	// Save to PEM format
	if err := SaveEd25519PrivateKeyToPEMFile(privateKey, tmpDir, "private.pem"); err != nil {
		t.Fatalf("failed to save private key to PEM: %v", err)
	}

	// Verify file permissions
	privateKeyPath := filepath.Join(tmpDir, "private.pem")
	info, err := os.Stat(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to stat PEM file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("PEM file permissions = %v, want 0600", info.Mode().Perm())
	}

	// load and compare private key
	loadedPrivateKey, err := ReadEd25519PrivateKeyFromPEMFile(tmpDir, "private.pem")
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	if !privateKey.Equal(loadedPrivateKey) {
		t.Error("loaded private key does not match original")
	}

	// public key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	if err := SaveEd25519PublicKeyToJWKFile(publicKey, keyID, tmpDir, "public.pem"); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	loadedPublicKey, err := ReadEd25519PublicKeyFromJWKFile(tmpDir, "public.pem")
	if err != nil {
		t.Fatalf("could not read public key from PEM file: %v", err)
	}

	if !publicKey.Equal(loadedPublicKey) {
		t.Errorf("loaded public key does not equal original public key")
	}
}

// TestSaveAndReadRSAJWK tests saving and loading RSA keys to and from JWK files
func TestSaveAndReadRSAJWK(t *testing.T) {
	// Generate a key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tmpDir := t.TempDir()
	keyID, err := GenerateKeyIDFromRSAKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to generate key ID: %v", err)
	}

	// Save to JWK format
	if err := SaveRSAPrivateKeyToJWKFile(privateKey, keyID, tmpDir, "private.jwk"); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}

	// Verify file permissions
	privateKeyPath := filepath.Join(tmpDir, "private.jwk")
	info, err := os.Stat(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to stat private key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("private key file permissions = %v, want 0600", info.Mode().Perm())
	}

	// load and compare private key
	loadedPrivateKey, err := ReadRSAPrivateKeyFromJWKFile(tmpDir, "private.jwk")
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	if !privateKey.Equal(loadedPrivateKey) {
		t.Error("loaded private key does not match original")
	}

	// public key
	publicKey := &privateKey.PublicKey

	if err := SaveRSAPublicKeyToJWKFile(publicKey, keyID, tmpDir, "public.jwk"); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	loadedPublicKey, err := ReadRSAPublicKeyFromJWKFile(tmpDir, "public.jwk")
	if err != nil {
		t.Fatalf("could not read public key from JWK file: %v", err)
	}

	if !publicKey.Equal(loadedPublicKey) {
		t.Errorf("loaded public key does not equal original public key")
	}
}

// TestSaveAndReadRSAPEM tests saving and loading RSA keys to and from PEM files
func TestSaveAndReadRSAPEM(t *testing.T) {
	// Generate a key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tmpDir := t.TempDir()
	// Save to PEM format
	if err := SaveRSAPrivateKeyToPEMFile(privateKey, tmpDir, "private.pem"); err != nil {
		t.Fatalf("failed to save private key to PEM: %v", err)
	}

	// Verify file permissions
	privateKeyPath := filepath.Join(tmpDir, "private.pem")
	info, err := os.Stat(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to stat PEM file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("PEM file permissions = %v, want 0600", info.Mode().Perm())
	}

	// load and compare private key
	loadedPrivateKey, err := ReadRSAPrivateKeyFromPEMFile(tmpDir, "private.pem")
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	if !privateKey.Equal(loadedPrivateKey) {
		t.Error("loaded private key does not match original")
	}

	// public key
	publicKey := &privateKey.PublicKey

	if err := SaveRSAPublicKeyToPEMFile(publicKey, tmpDir, "public.pem"); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	loadedPublicKey, err := ReadRSAPublicKeyFromPEMFile(tmpDir, "public.pem")
	if err != nil {
		t.Fatalf("could not read public key from PEM file: %v", err)
	}

	if !publicKey.Equal(loadedPublicKey) {
		t.Errorf("loaded public key does not equal original public key")
	}
}

// This test verifies that a key saved in both PEM and JWK formats is the same
func TestPEMAndJWKKeyPairMatch(t *testing.T) {

	t.Run("Ed25519", func(t *testing.T) {
		privateKey, err := GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}

		tmpDir := t.TempDir()

		// Save as PEM
		if err := SaveEd25519PrivateKeyToPEMFile(privateKey, tmpDir, "key.pem"); err != nil {
			t.Fatalf("failed to save PEM: %v", err)
		}

		// Save as JWK
		keyID := "test_kid"

		if err := SaveEd25519PrivateKeyToJWKFile(privateKey, keyID, tmpDir, "key.jwk"); err != nil {
			t.Fatalf("failed to save JWK: %v", err)
		}

		// Read both back
		pemKey, err := ReadEd25519PrivateKeyFromPEMFile(tmpDir, "key.pem")
		if err != nil {
			t.Fatalf("failed to read PEM: %v", err)
		}

		jwkKey, err := ReadEd25519PrivateKeyFromJWKFile(tmpDir, "key.jwk")
		if err != nil {
			t.Fatalf("failed to read JWK: %v", err)
		}

		// Verify they're the same
		if !pemKey.Equal(jwkKey) {
			t.Error("PEM and JWK keys do not match")
		}

		// Verify public keys match too
		if !pemKey.Public().(ed25519.PublicKey).Equal(jwkKey.Public().(ed25519.PublicKey)) {
			t.Error("PEM and JWK public keys do not match")
		}
	})

	t.Run("RSA", func(t *testing.T) {
		privateKey, err := GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}

		tmpDir := t.TempDir()

		// Save as PEM
		if err := SaveRSAPrivateKeyToPEMFile(privateKey, tmpDir, "key.pem"); err != nil {
			t.Fatalf("failed to save PEM: %v", err)
		}

		// Save as JWK
		keyID, err := GenerateKeyIDFromRSAKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to generate key ID: %v", err)
		}

		if err := SaveRSAPrivateKeyToJWKFile(privateKey, keyID, tmpDir, "key.jwk"); err != nil {
			t.Fatalf("failed to save JWK: %v", err)
		}

		// Read both back
		pemKey, err := ReadRSAPrivateKeyFromPEMFile(tmpDir, "key.pem")
		if err != nil {
			t.Fatalf("failed to read PEM: %v", err)
		}

		jwkKey, err := ReadRSAPrivateKeyFromJWKFile(tmpDir, "key.jwk")
		if err != nil {
			t.Fatalf("failed to read JWK: %v", err)
		}

		// Verify they're the same
		if !pemKey.Equal(jwkKey) {
			t.Error("PEM and JWK keys do not match")
		}

		// Verify public keys match too
		if !pemKey.PublicKey.Equal(&jwkKey.PublicKey) {
			t.Error("PEM and JWK public keys do not match")
		}
	})
}

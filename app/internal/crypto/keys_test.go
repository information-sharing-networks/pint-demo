package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndReadEd25519Keys(t *testing.T) {
	// private key
	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "private.pem")

	keyID, err := GenerateKeyIDFromEd25519Key(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("failed to generate key ID: %v", err)
	}

	if err := SaveEd25519PrivateKeyToJWKFile(privateKey, keyID, privateKeyPath); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}

	loadedPrivateKey, err := ReadEd25519PrivateKeyFromJWKFile(privateKeyPath)
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
	publicKeyPath := filepath.Join(tmpDir, "public.pem")
	publicKey := privateKey.Public().(ed25519.PublicKey)

	if err := SaveEd25519PublicKeyToJWKFile(publicKey, keyID, publicKeyPath); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	loadedPublicKey, err := ReadEd25519PublicKeyFromJWKFile(publicKeyPath)
	if err != nil {
		t.Fatalf("could not read public key from PEM file: %v", err)
	}

	if !publicKey.Equal(loadedPublicKey) {
		t.Errorf("loaded public key does not equal original public key")
	}

}
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

func TestSaveAndReadRSAKeys(t *testing.T) {

	// private key
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("could not generate RSA key %v", err)
	}
	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "private.pem")

	keyID, err := GenerateKeyIDFromRSAKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to generate key ID: %v", err)
	}

	err = SaveRSAPrivateKeyToJWKFile(privateKey, keyID, privateKeyPath)
	if err != nil {
		t.Fatalf("error saving PEM file: %v", err)
	}

	loadedPrivateKey, err := ReadRSAPrivateKeyFromJWKFile(privateKeyPath)
	if err != nil {
		t.Fatalf("error reading PEM file: %v", err)
	}

	if !privateKey.Equal(loadedPrivateKey) {
		t.Errorf("loaded private key does not match original")
	}

	// check perms
	info, err := os.Stat(privateKeyPath)
	if err != nil {
		t.Fatalf("could not stat file %v: %v", privateKeyPath, err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("private key file permissions = %v, want 0600", info.Mode().Perm())
	}

	// public key
	publicKeyPath := filepath.Join(tmpDir, "public.pem")

	publicKey := &privateKey.PublicKey

	if err := SaveRSAPublicKeyToJWKFile(publicKey, keyID, publicKeyPath); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	if err := SaveRSAPublicKeyToJWKFile(publicKey, keyID, publicKeyPath); err != nil {
		t.Fatalf("could not save public key PEM file: %v", err)
	}

	loadedPublicKey, err := ReadRSAPublicKeyFromJWKFile(publicKeyPath)
	if err != nil {
		t.Fatalf("could not read public key from file: %v", err)
	}

	if !publicKey.Equal(loadedPublicKey) {
		t.Errorf("loaded public key does not equal orginal: %v", err)
	}

}

func TestSaveAndReadEd25519PrivateKeyPEM(t *testing.T) {
	// Generate a key pair
	privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "private.pem")

	// Save to PEM format
	if err := SaveEd25519PrivateKeyToPEMFile(privateKey, pemPath); err != nil {
		t.Fatalf("failed to save private key to PEM: %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(pemPath)
	if err != nil {
		t.Fatalf("failed to stat PEM file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("PEM file permissions = %v, want 0600", info.Mode().Perm())
	}

	// Read back using the generic PEM reader
	loadedKey, err := ReadPrivateKeyFromPEMFile(pemPath)
	if err != nil {
		t.Fatalf("failed to read private key from PEM: %v", err)
	}

	// Type assert to Ed25519
	loadedPrivateKey, ok := loadedKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("loaded key is not Ed25519, got type: %T", loadedKey)
	}

	// Compare keys
	if !privateKey.Equal(loadedPrivateKey) {
		t.Error("loaded private key does not match original")
	}
}

func TestSaveAndReadRSAPrivateKeyPEM(t *testing.T) {
	// Generate a key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "private.pem")

	// Save to PEM format
	if err := SaveRSAPrivateKeyToPEMFile(privateKey, pemPath); err != nil {
		t.Fatalf("failed to save private key to PEM: %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(pemPath)
	if err != nil {
		t.Fatalf("failed to stat PEM file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("PEM file permissions = %v, want 0600", info.Mode().Perm())
	}

	// Read back using the generic PEM reader
	loadedKey, err := ReadPrivateKeyFromPEMFile(pemPath)
	if err != nil {
		t.Fatalf("failed to read private key from PEM: %v", err)
	}

	// Type assert to RSA
	loadedPrivateKey, ok := loadedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("loaded key is not RSA, got type: %T", loadedKey)
	}

	// Compare keys
	if !privateKey.Equal(loadedPrivateKey) {
		t.Error("loaded private key does not match original")
	}
}

func TestPEMAndJWKKeyPairMatch(t *testing.T) {
	// This test verifies that a key saved in both PEM and JWK formats

	t.Run("Ed25519", func(t *testing.T) {
		privateKey, err := GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}

		tmpDir := t.TempDir()

		// Save as PEM
		pemPath := filepath.Join(tmpDir, "key.pem")
		if err := SaveEd25519PrivateKeyToPEMFile(privateKey, pemPath); err != nil {
			t.Fatalf("failed to save PEM: %v", err)
		}

		// Save as JWK
		keyID, err := GenerateKeyIDFromEd25519Key(privateKey.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatalf("failed to generate key ID: %v", err)
		}

		jwkPath := filepath.Join(tmpDir, "key.jwk")
		if err := SaveEd25519PrivateKeyToJWKFile(privateKey, keyID, jwkPath); err != nil {
			t.Fatalf("failed to save JWK: %v", err)
		}

		// Read both back
		pemKey, err := ReadPrivateKeyFromPEMFile(pemPath)
		if err != nil {
			t.Fatalf("failed to read PEM: %v", err)
		}

		jwkKey, err := ReadEd25519PrivateKeyFromJWKFile(jwkPath)
		if err != nil {
			t.Fatalf("failed to read JWK: %v", err)
		}

		// Verify they're the same
		pemPrivateKey := pemKey.(ed25519.PrivateKey)
		if !pemPrivateKey.Equal(jwkKey) {
			t.Error("PEM and JWK keys do not match")
		}

		// Verify public keys match too
		if !pemPrivateKey.Public().(ed25519.PublicKey).Equal(jwkKey.Public().(ed25519.PublicKey)) {
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
		pemPath := filepath.Join(tmpDir, "key.pem")
		if err := SaveRSAPrivateKeyToPEMFile(privateKey, pemPath); err != nil {
			t.Fatalf("failed to save PEM: %v", err)
		}

		// Save as JWK
		keyID, err := GenerateKeyIDFromRSAKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to generate key ID: %v", err)
		}

		jwkPath := filepath.Join(tmpDir, "key.jwk")
		if err := SaveRSAPrivateKeyToJWKFile(privateKey, keyID, jwkPath); err != nil {
			t.Fatalf("failed to save JWK: %v", err)
		}

		// Read both back
		pemKey, err := ReadPrivateKeyFromPEMFile(pemPath)
		if err != nil {
			t.Fatalf("failed to read PEM: %v", err)
		}

		jwkKey, err := ReadRSAPrivateKeyFromJWKFile(jwkPath)
		if err != nil {
			t.Fatalf("failed to read JWK: %v", err)
		}

		// Verify they're the same
		pemPrivateKey := pemKey.(*rsa.PrivateKey)
		if !pemPrivateKey.Equal(jwkKey) {
			t.Error("PEM and JWK keys do not match")
		}

		// Verify public keys match too
		if !pemPrivateKey.PublicKey.Equal(&jwkKey.PublicKey) {
			t.Error("PEM and JWK public keys do not match")
		}
	})
}

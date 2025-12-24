package crypto

import (
	"crypto/ed25519"
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

	if err := SaveEd25519PrivateKeyToFile(privateKey, keyID, privateKeyPath); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}

	loadedPrivateKey, err := ReadEd25519PrivateKeyFromFile(privateKeyPath)
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

	if err := SaveEd25519PublicKeyToFile(publicKey, keyID, publicKeyPath); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	loadedPublicKey, err := ReadEd25519PublicKeyFromFile(publicKeyPath)
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

	err = SaveRSAPrivateKeyToFile(privateKey, keyID, privateKeyPath)
	if err != nil {
		t.Fatalf("error saving PEM file: %v", err)
	}

	loadedPrivateKey, err := ReadRSAPrivateKeyFromFile(privateKeyPath)
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

	if err := SaveRSAPublicKeyToFile(publicKey, keyID, publicKeyPath); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	if err := SaveRSAPublicKeyToFile(publicKey, keyID, publicKeyPath); err != nil {
		t.Fatalf("could not save public key PEM file: %v", err)
	}

	loadedPublicKey, err := ReadRSAPublicKeyFromFile(publicKeyPath)
	if err != nil {
		t.Fatalf("could not read public key from file: %v", err)
	}

	if !publicKey.Equal(loadedPublicKey) {
		t.Errorf("loaded public key does not equal orginal: %v", err)
	}

}

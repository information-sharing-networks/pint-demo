package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

var testData = []byte("hello world")
var expectedChecksum = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

func TestCalculateSHA256FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	// Create test file
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Calculate checksum
	result, err := CalculateSHA256FromFile(testFile)
	if err != nil {
		t.Fatalf("CalculateSHA256FromFile() error = %v", err)
	}

	if result != expectedChecksum {
		t.Errorf("CalculateSHA256FromFile() = %v, want %v", result, expectedChecksum)
	}

	// Test non-existent file
	_, err = CalculateSHA256FromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestVerifyFileChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	// Create test file
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	invalidChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

	// Valid checksum should return true
	result, err := VerifyFileChecksum(testFile, expectedChecksum)
	if err != nil {
		t.Fatalf("error occured when trying to verify checksum: %v", err)
	}
	if !result {
		t.Error("VerifyFileChecksum() should return true for valid checksum")
	}

	// Invalid checksum should return false
	result, err = VerifyFileChecksum(testFile, invalidChecksum)
	if err != nil {
		t.Fatalf("VerifyFileChecksum() error = %v", err)
	}
	if result {
		t.Error("VerifyFileChecksum() should return false for invalid checksum")
	}

	// Non-existent file should return error
	result, err = VerifyFileChecksum("/nonexistent/file.txt", expectedChecksum)
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
	if result {
		t.Error("expected false result for non-existent file")
	}
}

// this file contains functions to calculate and verify SHA-256 checksums
//
// the DCSA standard requires that SHA-256 is used to calculate checksums.

package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// CalculateSHA256Hex calculates the SHA-256 checksum of data and returns it as a hex string
func CalculateSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CalculateSHA256FromFile calculates the SHA-256 checksum of a file
func CalculateSHA256FromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()

	_, err = io.Copy(hasher, file)
	if err != nil {
		return "", fmt.Errorf("failed to copy file contents: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyChecksum verifies that data matches the expected SHA-256 checksum
func VerifyChecksum(data []byte, expectedChecksum string) bool {
	checksum := CalculateSHA256Hex(data)
	return checksum == expectedChecksum
}

// VerifyFileChecksum verifies that a file matches the expected SHA-256 checksum
func VerifyFileChecksum(filepath string, expectedChecksum string) (bool, error) {
	checksum, err := CalculateSHA256FromFile(filepath)
	if err != nil {
		return false, err
	}
	return checksum == expectedChecksum, nil
}

// this file provides SHA-256 hashing functions compliant with DCSA specifications.
//
// DCSA requires SHA-256 hashes (called "checksums" in the spec) for:
//   1. Canonical JSON documents (transport docs, issueTo, etc.)
//   2. Binary content decoded from base64 (eBL visualizations/associated documents)
//   3. JWS strings (transfer chain entries)

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Hash calculates SHA-256 checksum (hash) and returns hex string.
//
// This is the checksum algorithm required by DCSA.
//
// Use this for:
// - Canonical JSON
// - JWS strings
// - Any data already in memory
//
// For base64-encoded binary content, use HashFromBase64 instead.
func Hash(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("data is empty")
	}
	hasher := sha256.New()

	if _, err := io.Copy(hasher, bytes.NewReader(data)); err != nil {
		return "", fmt.Errorf("failed to hash data: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// HashFromBase64 decodes base64-encoded content and returns a DCSA-compliant checksum
//
// use this function when you have base64-encoded binary content (e.g. PDF visualizations)
//
// Per DCSA spec: The checksum is calculated over the decoded binary content, not the base64 string.
func HashFromBase64(encoded string, maxSize int64) (string, error) {

	if len(encoded) == 0 {
		return "", fmt.Errorf("data is empty")
	}
	// Check base64 input size
	if int64(len(encoded)) > maxSize {
		return "", fmt.Errorf("base64 content size (%d bytes) exceeds maximum (%d bytes)",
			len(encoded), maxSize)
	}

	// decode before hashing - stream decode to avoid loading large PDFs into memory
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))
	hasher := sha256.New()

	if _, err := io.Copy(hasher, decoder); err != nil {
		return "", fmt.Errorf("invalid base64 content: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyHash verifies that data matches the expected SHA-256 checksum.
func VerifyHash(data []byte, expectedChecksum string) bool {
	checksum, _ := Hash(data)
	return checksum == expectedChecksum
}

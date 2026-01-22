// this file provides SHA-256 hashing functions compliant with DCSA specifications.
//
// these are low level functions - for standard usage (issuance requests, transfer requests etc) you will not need to call these functions directly.
//
// DCSA requires SHA-256 hashes (called "checksums" in the spec) for:
//   1. Canonical JSON documents (transport docs, issueTo, etc.)
//   2. Binary content decoded from base64 (eBL Visualisations/associated documents)
//   3. JWS strings (transfer chain entries)

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
		return "", NewValidationError("data is empty")
	}
	hasher := sha256.New()

	if _, err := io.Copy(hasher, bytes.NewReader(data)); err != nil {
		return "", WrapInternalError(err, "failed to hash data")
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// HashFromBase64 decodes base64-encoded content and returns a DCSA-compliant checksum
//
// use this function when you have base64-encoded binary content (e.g. PDF Visualisations)
//
// Per DCSA spec: The checksum is calculated over the decoded binary content, not the base64 string.
//
// TODO: this function requires the entire base64-encoded string in memory
// (unavoidable for eblVisualisationByCarrier.Content since JSON unmarshaling already loaded it)
// The streaming decode avoids creating a second copy of the decoded bytes.
// Revisit when handling associated docs - those could potentially be streamed from client...
func HashFromBase64(encoded string, maxSize int64) (string, error) {

	if len(encoded) == 0 {
		return "", NewValidationError("data is empty")
	}
	// Check base64 input size
	if int64(len(encoded)) > maxSize {
		return "", NewValidationError("base64 content exceeds maximum size")
	}

	// decode before hashing - stream decode to reduce memory overhead
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))
	hasher := sha256.New()

	if _, err := io.Copy(hasher, decoder); err != nil {
		return "", WrapValidationError(err, "invalid base64 content")
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyHash verifies that data matches the expected SHA-256 checksum.
func VerifyHash(data []byte, expectedChecksum string) bool {
	checksum, _ := Hash(data)
	return checksum == expectedChecksum
}

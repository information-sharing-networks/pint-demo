//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

// decodeSignedFinishedResponse decodes a SignedEnvelopeTransferFinishedResponse
// and returns the payload (assumes the signature is valid)
func decodeSignedFinishedResponse(t *testing.T, signedResp pint.SignedEnvelopeTransferFinishedResponse) pint.EnvelopeTransferFinishedResponse {
	t.Helper()

	// JWS format is header.payload.signature
	parts := strings.Split(signedResp.SignedContent, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode the base64url-encoded payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode JWS payload: %v", err)
	}

	// Unmarshal the JSON payload
	var payload pint.EnvelopeTransferFinishedResponse
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	return payload
}

// TestStartTransfer does an end-2-end test of the POST /v3/envelopes endpointd
func TestStartTransfer(t *testing.T) {
	ctx := context.Background()
	testDB := setupCleanDatabase(t, ctx)
	testEnv := setupTestEnvironment(testDB)
	testDatabaseURL := getDatabaseURL()
	baseURL, stopServer := startInProcessServer(t, ctx, testEnv.dbConn, testDatabaseURL)
	defer stopServer()

	envelopesURL := baseURL + "/v3/envelopes"
	// the test envelope with additional documents (1 ebl visualization, 2 supporting documents)
	testEnvelopeWithDocsPath := "../../internal/crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"

	// test envelope with no additional documents
	testEnvelopeNoDocsPath := "../../internal/crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-nodocs-ed25519.json"

	testData := []struct {
		name                 string
		envelopePath         string
		expectedStatus       int
		expectedError        string
		expectedMissingDocs  int
		expectedReceivedDocs int
	}{
		{
			name:                 "valid envelope with additional documents",
			envelopePath:         testEnvelopeWithDocsPath,
			expectedStatus:       http.StatusCreated, // should be created but not accepted
			expectedMissingDocs:  3,
			expectedReceivedDocs: 0,
		},
		{
			name:                 "valid envelope with no additional documents",
			envelopePath:         testEnvelopeNoDocsPath,
			expectedStatus:       http.StatusOK, // should be immediately accepted
			expectedMissingDocs:  0,
			expectedReceivedDocs: 0,
		},
	}
	for _, test := range testData {
		t.Run(test.name, func(t *testing.T) {
			defer cleanupDatabase(t, testDB) // Clean database after each subtest

			// Load valid test envelope
			envelopeData, err := os.ReadFile(test.envelopePath)
			if err != nil {
				t.Fatalf("Failed to read test envelope: %v", err)
			}

			// Parse the envelope to extract transport document and transfer chain for checksum validation
			var testEnvelope map[string]json.RawMessage
			if err := json.Unmarshal(envelopeData, &testEnvelope); err != nil {
				t.Fatalf("Failed to parse test envelope: %v", err)
			}

			// Calculate expected transport document checksum
			canonicalTransportDoc, err := crypto.CanonicalizeJSON(testEnvelope["transportDocument"])
			if err != nil {
				t.Fatalf("Failed to canonicalize transport document: %v", err)
			}
			expectedTransportDocChecksum, err := crypto.Hash(canonicalTransportDoc)
			if err != nil {
				t.Fatalf("Failed to hash transport document: %v", err)
			}

			// Parse transfer chain to get the last entry (array of JWS strings)
			var transferChain []string
			if err := json.Unmarshal(testEnvelope["envelopeTransferChain"], &transferChain); err != nil {
				t.Fatalf("Failed to parse transfer chain: %v", err)
			}
			if len(transferChain) == 0 {
				t.Fatal("Transfer chain is empty")
			}

			// Calculate expected last chain entry checksum (hash of the JWS string)
			lastChainEntryJWS := transferChain[len(transferChain)-1]
			expectedLastChainChecksum, err := crypto.Hash([]byte(lastChainEntryJWS))
			if err != nil {
				t.Fatalf("Failed to hash last chain entry: %v", err)
			}

			// ===== Initial transfer =====
			t.Log("Step 1: POST initial envelope transfer")
			resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
			if err != nil {
				t.Fatalf("Failed to POST envelope: %v", err)
			}
			defer resp.Body.Close()

			// Verify status code
			if resp.StatusCode != test.expectedStatus {
				t.Fatalf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
			}

			// Verify Content-Type
			contentType := resp.Header.Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
			}

			// immediate acceptance - no additional documents, check the RECE response
			if resp.StatusCode == http.StatusOK {

				var parsedResponse pint.SignedEnvelopeTransferFinishedResponse
				if err := json.NewDecoder(resp.Body).Decode(&parsedResponse); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				payload := decodeSignedFinishedResponse(t, parsedResponse)
				if payload.ResponseCode != pint.ResponseCodeRECE {
					t.Errorf("Expected responseCode 'RECE', got '%s'", payload.ResponseCode)
				}
				if len(payload.MissingAdditionalDocumentChecksums) != test.expectedMissingDocs {
					t.Errorf("Expected %d missing additional documents, got %d", test.expectedMissingDocs, len(payload.MissingAdditionalDocumentChecksums))
				}
				if len(payload.ReceivedAdditionalDocumentChecksums) != test.expectedReceivedDocs {
					t.Errorf("Expected %d received additional documents, got %d", test.expectedReceivedDocs, len(payload.ReceivedAdditionalDocumentChecksums))
				}
				t.Logf("✓ Initial transfer: Accepted with 200/RECE response")
			}

			if resp.StatusCode == http.StatusCreated {
				// Parse parsedResponse
				var parsedResponse pint.EnvelopeTransferStartedResponse
				if err := json.NewDecoder(resp.Body).Decode(&parsedResponse); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				// Verify response structure
				if parsedResponse.EnvelopeReference == "" {
					t.Error("Expected envelopeReference to be set")
				}

				// Verify transportDocumentChecksum matches the actual SHA-256 of the transport document
				if parsedResponse.TransportDocumentChecksum != expectedTransportDocChecksum {
					t.Errorf("TransportDocumentChecksum mismatch:\n  expected: %s\n  got:      %s",
						expectedTransportDocChecksum, parsedResponse.TransportDocumentChecksum)
				}

				// Verify lastEnvelopeTransferChainEntrySignedContentChecksum matches the actual SHA-256 of the last chain entry
				if parsedResponse.LastEnvelopeTransferChainEntrySignedContentChecksum != expectedLastChainChecksum {
					t.Errorf("LastEnvelopeTransferChainEntrySignedContentChecksum mismatch:\n  expected: %s\n  got:      %s",
						expectedLastChainChecksum, parsedResponse.LastEnvelopeTransferChainEntrySignedContentChecksum)
				}

				// MissingAdditionalDocumentChecksums should be an array (may be empty or populated)
				if parsedResponse.MissingAdditionalDocumentChecksums == nil {
					t.Error("Expected missingAdditionalDocumentChecksums to be set (even if empty)")
				}

				// Verify database record was created
				envelopeRef, err := uuid.Parse(parsedResponse.EnvelopeReference)
				if err != nil {
					t.Fatalf("Failed to parse envelope reference UUID: %v", err)
				}

				envelope, err := testEnv.queries.GetEnvelopeByReference(ctx, envelopeRef)
				if err != nil {
					t.Fatalf("Failed to retrieve envelope from database: %v", err)
				}

				if envelope.TransportDocumentChecksum != parsedResponse.TransportDocumentChecksum {
					t.Errorf("Database checksum mismatch: expected %s, got %s",
						parsedResponse.TransportDocumentChecksum, envelope.TransportDocumentChecksum)
				}

				if envelope.State != "PENDING" {
					t.Errorf("Expected envelope state 'PENDING', got '%s'", envelope.State)
				}

				// Verify trust level is stored correctly (3 = TrustLevelEVOV)
				if envelope.TrustLevel != 3 {
					t.Errorf("Expected trust level 3 (EV/OV), got %d", envelope.TrustLevel)
				}

				// Verify transfer chain entries were stored
				chainEntries, err := testEnv.queries.ListTransferChainEntries(ctx, envelope.ID)
				if err != nil {
					t.Fatalf("Failed to retrieve transfer chain entries: %v", err)
				}

				if len(chainEntries) == 0 {
					t.Error("Expected transfer chain entries to be stored")
				}

				// Verify the response checksum matches what's stored in the database
				if parsedResponse.LastEnvelopeTransferChainEntrySignedContentChecksum != envelope.LastTransferChainEntryChecksum {
					t.Errorf("Expected lastEnvelopeTransferChainEntrySignedContentChecksum to match database value: expected %s, got %s",
						envelope.LastTransferChainEntryChecksum, parsedResponse.LastEnvelopeTransferChainEntrySignedContentChecksum)
				}

				// check the response identifies the expected missing docs
				if len(parsedResponse.MissingAdditionalDocumentChecksums) != test.expectedMissingDocs {
					t.Errorf("Expected %d missing additional documents, got %d", test.expectedMissingDocs, len(parsedResponse.MissingAdditionalDocumentChecksums))
				}

				t.Logf("✓ Initial transfer: started with 201 response")
			}

			// ===== Second POST: Duplicate detection =====
			t.Log("Step 2: POST duplicate envelope transfer (same envelope)")

			resp2, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
			if err != nil {
				t.Fatalf("Failed to POST duplicate envelope: %v", err)
			}
			defer resp2.Body.Close()

			// Verify status code (duplicates return 200 OK, not 201)
			if resp2.StatusCode != http.StatusOK {
				t.Fatalf("Expected status %d for duplicate, got %d", http.StatusOK, resp2.StatusCode)
			}

			// Verify Content-Type
			contentType2 := resp2.Header.Get("Content-Type")
			if contentType2 != "application/json" {
				t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType2)
			}

			// Parse response (dupes return 200 with a signed response)
			var signedResponse pint.SignedEnvelopeTransferFinishedResponse
			if err := json.NewDecoder(resp2.Body).Decode(&signedResponse); err != nil {
				t.Fatalf("Failed to decode duplicate response: %v", err)
			}

			// Verify the signed content is present
			if signedResponse.SignedContent == "" {
				t.Fatal("Expected signedContent to be set")
			}

			// Decode the JWS payload
			payload := decodeSignedFinishedResponse(t, signedResponse)

			// Verify the response code is DUPE
			if payload.ResponseCode != pint.ResponseCodeDUPE {
				t.Errorf("Expected responseCode 'DUPE', got '%s'", payload.ResponseCode)
			}

			// Verify lastEnvelopeTransferChainEntrySignedContentChecksum matches the expected value
			if payload.LastEnvelopeTransferChainEntrySignedContentChecksum != expectedLastChainChecksum {
				t.Errorf("Duplicate response LastEnvelopeTransferChainEntrySignedContentChecksum mismatch:\n  expected: %s\n  got:      %s",
					expectedLastChainChecksum, payload.LastEnvelopeTransferChainEntrySignedContentChecksum)
			}

			// Verify duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent is set
			if payload.DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent == nil {
				t.Error("Expected duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent to be set")
			} else {
				// Verify it's a valid JWS format (header.payload.signature)
				parts := strings.Split(*payload.DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent, ".")
				if len(parts) != 3 {
					t.Errorf("Expected duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent to be valid JWS format, got %d parts", len(parts))
				}

				// Verify it matches the last chain entry from the original envelope
				if lastChainEntryJWS != *payload.DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent {
					t.Errorf("DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent does not match original last chain entry")
				}
			}
			// check the missing additional docs is still present
			if len(payload.MissingAdditionalDocumentChecksums) != test.expectedMissingDocs {
				t.Errorf("Expected %d missing additional documents, got %d", test.expectedMissingDocs, len(payload.MissingAdditionalDocumentChecksums))
			}

			// check the received additional docs is empty
			if len(payload.ReceivedAdditionalDocumentChecksums) != 0 {
				t.Errorf("Expected 0 received additional documents, got %d", len(payload.ReceivedAdditionalDocumentChecksums))
			}
			t.Logf("✓ Duplicate detection: Successfully detected with response code: %s", payload.ResponseCode)
		})
		t.Run("malformed JSON returns 400 Bad Request", func(t *testing.T) {
			malformedJSON := []byte(`{"invalid": json}`)

			resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(malformedJSON))
			if err != nil {
				t.Fatalf("Failed to POST envelope: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", resp.StatusCode)
			}

			// Parse error response
			var errorResp pint.ErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
				t.Fatalf("Failed to decode error response: %v", err)
			}

			if errorResp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected error statusCode 400, got %d", errorResp.StatusCode)
			}

			//spew.Dump(errorResp)
			if len(errorResp.Errors) == 0 {
				t.Error("Expected errors array to be populated")
			}
			t.Logf("✓ Malformed JSON: Received error response: %s", errorResp.Errors[0].ErrorCodeText)
		})

		t.Run("tampered envelope returns 422 Unprocessable Entity", func(t *testing.T) {
			// Load valid test envelope
			envelopeData, err := os.ReadFile(testEnvelopeWithDocsPath)
			if err != nil {
				t.Fatalf("Failed to read test envelope: %v", err)
			}

			// Parse and tamper with the envelope
			var envelope map[string]any
			if err := json.Unmarshal(envelopeData, &envelope); err != nil {
				t.Fatalf("Failed to parse envelope: %v", err)
			}

			// Tamper with the transport document
			envelope["transportDocument"] = map[string]any{
				"tampered": "data",
			}

			tamperedData, err := json.Marshal(envelope)
			if err != nil {
				t.Fatalf("Failed to marshal tampered envelope: %v", err)
			}

			// POST the tampered envelope
			resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(tamperedData))
			if err != nil {
				t.Fatalf("Failed to POST envelope: %v", err)
			}
			defer resp.Body.Close()

			// Should return 422 Bad Request (envelope verification failed)
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("Expected status 422, got %d", resp.StatusCode)
			}

			// Decode the signed response
			var signedResp pint.SignedEnvelopeTransferFinishedResponse
			if err := json.NewDecoder(resp.Body).Decode(&signedResp); err != nil {
				t.Fatalf("Failed to decode signed response: %v", err)
			}

			// Decode the JWS payload
			payload := decodeSignedFinishedResponse(t, signedResp)

			// Verify the response code is BENV (bad envelope)
			if payload.ResponseCode != pint.ResponseCodeBENV {
				t.Errorf("Expected responseCode 'BENV', got '%s'", payload.ResponseCode)
			}

			// Verify the reason is populated
			if payload.Reason == nil || *payload.Reason == "" {
				t.Error("Expected reason to be populated for BENV response")
			}
			//t.Logf("Rejection reason: %s", *payload.Reason)

			// Verify lastEnvelopeTransferChainEntrySignedContentChecksum is set
			if payload.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
				t.Error("Expected lastEnvelopeTransferChainEntrySignedContentChecksum to be set")
			}

			t.Logf("✓ Tampered envelope: Received BENV response")
		})
	}
}

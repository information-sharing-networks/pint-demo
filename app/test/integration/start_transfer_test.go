//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

// TestStartTransfer does an end-2-end test of the POST /v3/envelopes endpointd
// TODO tests for multiple/inconsistent/missing identifying codes
// TODO move recipient party tests to use new helper
func TestStartTransfer(t *testing.T) {
	testEnv := startInProcessServer(t, "EBL2")
	defer testEnv.shutdown()
	createValidParties(t, testEnv)

	envelopesURL := testEnv.baseURL + "/v3/envelopes"
	// the test envelope with additional documents (1 ebl visualization, 2 supporting documents)
	testEnvelopeWithDocsPath := "../testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"

	// test envelope with no additional documents
	testEnvelopeNoDocsPath := "../testdata/pint-transfers/HHL71800000-ebl-envelope-nodocs-ed25519.json"

	testData := []struct {
		name                 string
		envelopePath         string
		expectedStatus       int
		expectedError        string
		expectedMissingDocs  int
		expectedReceivedDocs int
		isRetry              bool
		resetDatabase        bool
	}{
		{
			name:                 "accepts envelope with additional documents",
			envelopePath:         testEnvelopeWithDocsPath,
			expectedStatus:       http.StatusCreated, // should be created but not accepted
			expectedMissingDocs:  3,
			expectedReceivedDocs: 0,
		},
		{
			name:                 "retry: returns pending state for envelope with additional documents",
			envelopePath:         testEnvelopeWithDocsPath,
			expectedStatus:       http.StatusCreated, // should report dupe
			expectedMissingDocs:  3,
			expectedReceivedDocs: 0,
			isRetry:              true,
		},
		{
			name:                 "accepts envelope with no additional documents immediately",
			envelopePath:         testEnvelopeNoDocsPath,
			expectedStatus:       http.StatusOK, // should be immediately accepted
			expectedMissingDocs:  0,
			expectedReceivedDocs: 0,
			resetDatabase:        true,
		},
		{
			name:                 "retry: returns DUPE for envelope with no additional documents",
			envelopePath:         testEnvelopeNoDocsPath,
			expectedStatus:       http.StatusOK, // should be immediately accepted
			expectedMissingDocs:  0,
			expectedReceivedDocs: 0,
			isRetry:              true,
		},
	}
	for _, test := range testData {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.resetDatabase {
				t.Log("Resetting database for test")
				cleanupDatabase(t, testEnv.pool)
				createValidParties(t, testEnv)
			}

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

				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)
				payload := decodeSignedFinishedResponse(t, signedResponse)
				if test.isRetry {
					if payload.ResponseCode != pint.ResponseCodeDUPE {
						t.Errorf("Expected responseCode 'DUPE', got '%s'", payload.ResponseCode)
					}
				} else {
					if payload.ResponseCode != pint.ResponseCodeRECE {
						t.Errorf("Expected responseCode 'RECE', got '%s'", payload.ResponseCode)
					}
				}
				if len(payload.MissingAdditionalDocumentChecksums) != test.expectedMissingDocs {
					t.Errorf("Expected %d missing additional documents, got %d", test.expectedMissingDocs, len(payload.MissingAdditionalDocumentChecksums))
				}
				if len(*payload.ReceivedAdditionalDocumentChecksums) != test.expectedReceivedDocs {
					t.Errorf("Expected %d received additional documents, got %d", test.expectedReceivedDocs, len(*payload.ReceivedAdditionalDocumentChecksums))
				}
				t.Logf("transfer accepted with 200/%v response", payload.ResponseCode)

				// get the envelope reference from the last transfer chain entry checksum (the response does not contain the envelope reference)
				envelope, err := testEnv.queries.GetEnvelopeByLastChainEntryChecksum(ctx, expectedLastChainChecksum)
				if err != nil {
					t.Fatalf("Failed to retrieve envelope from database: %v", err)
				}

				if envelope.ID == uuid.Nil {
					t.Fatalf("Expected envelope reference to be set")
				}

				// Verify response_code is RECE in database (immediate accept)
				if envelope.ResponseCode == nil {
					t.Errorf("Expected envelope response_code to be 'RECE', got NULL")
				} else if *envelope.ResponseCode != string(pint.ResponseCodeRECE) {
					t.Errorf("Expected envelope response_code to be 'RECE', got '%s'", *envelope.ResponseCode)
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
				// walk backwards throught he chain and verify the previous entry checksums
				for i := len(chainEntries) - 1; i > 0; i-- {
					if chainEntries[i].PreviousEntryChecksum == nil {
						t.Errorf("Expected previous entry checksum to be set for entry %d", i)
					} else {
						if *chainEntries[i].PreviousEntryChecksum != chainEntries[i-1].EntryChecksum {
							t.Errorf("Previous entry checksum mismatch for entry %d: expected %s, got %s", i, chainEntries[i-1].EntryChecksum, *chainEntries[i].PreviousEntryChecksum)
						}
					}
				}
			}

			// transfer started, but not yet accepted (documents outstanding)
			if resp.StatusCode == http.StatusCreated {
				// Parse the response
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

				// Verify envelope is pending (response_code is NULL)
				if envelope.ResponseCode != nil {
					t.Errorf("Expected envelope response_code to be NULL (pending), got '%s'", *envelope.ResponseCode)
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
				// walk backwards throught he chain and verify the previous entry checksums
				for i := len(chainEntries) - 1; i > 0; i-- {
					if chainEntries[i].PreviousEntryChecksum == nil {
						t.Errorf("Expected previous entry checksum to be set for entry %d", i)
					} else {
						if *chainEntries[i].PreviousEntryChecksum != chainEntries[i-1].EntryChecksum {
							t.Errorf("Previous entry checksum mismatch for entry %d: expected %s, got %s", i, chainEntries[i-1].EntryChecksum, *chainEntries[i].PreviousEntryChecksum)
						}
					}
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

				t.Logf("transfer started but docs outstanding (201 response)")
			}
		})

	}
	t.Run("error: malformed JSON returns 400 Bad Request", func(t *testing.T) {
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
		t.Logf("Malformed JSON: Received error response: %s", errorResp.Errors[0].ErrorCodeText)
	})

	// skip this test
	t.Run("error: tampered envelope returns 422 with BENV", func(t *testing.T) {
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

		// Read the signed response
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		SignedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)

		// Decode the JWS payload
		payload := decodeSignedFinishedResponse(t, SignedResponse)

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

		t.Logf("Tampered envelope: Received BENV response")
	})
}

// TestStartTransfer_RecipientPlatformValidation tests that envelopes addressed to the wrong platform are rejected
func TestStartTransfer_RecipientPlatformValidation(t *testing.T) {
	// The test envelope (Ed25519) is addressed to EBL2 (sender=EBL1, recipient=EBL2)
	testEnvelopePath := "../testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"

	tests := []struct {
		name            string
		serverPlatform  string // What platform code to start the server as
		expectedStatus  int
		expectedCode    pint.ResponseCode
		wantErrContains string
	}{
		{
			name:           "accepts envelope addressed to correct platform",
			serverPlatform: "EBL2",
			expectedStatus: http.StatusCreated,
		},
		{
			name:            "returns BENV when envelope addressed to wrong platform",
			serverPlatform:  "EBL1",
			expectedStatus:  http.StatusUnprocessableEntity,
			expectedCode:    pint.ResponseCodeBENV,
			wantErrContains: "envelope is addressed to platform EBL2 but this platform is EBL1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start server as the specified platform
			env := startInProcessServer(t, tt.serverPlatform)
			defer env.shutdown()
			createValidParties(t, env)

			envelopesURL := env.baseURL + "/v3/envelopes"

			// Load and POST the envelope
			envelopeData, err := os.ReadFile(testEnvelopePath)
			if err != nil {
				t.Fatalf("Failed to read test envelope: %v", err)
			}

			resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
			if err != nil {
				t.Fatalf("Failed to POST envelope: %v", err)
			}
			defer resp.Body.Close()

			// Verify status code
			if resp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.expectedStatus == http.StatusUnprocessableEntity {
				// Read the signed error response
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)

				// Decode the JWS payload
				payload := decodeSignedFinishedResponse(t, signedResponse)

				// Verify the response code is BENV
				if payload.ResponseCode != tt.expectedCode {
					t.Errorf("Expected responseCode %q, got %q", tt.expectedCode, payload.ResponseCode)
				}

				// Verify the reason contains expected error
				if payload.Reason == nil || !strings.Contains(*payload.Reason, tt.wantErrContains) {
					t.Errorf("Expected reason to contain %q, got %v", tt.wantErrContains, payload.Reason)
				}

				// Verify lastEnvelopeTransferChainEntrySignedContentChecksum is set
				if payload.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
					t.Error("Expected lastEnvelopeTransferChainEntrySignedContentChecksum to be set")
				}

			}
		})
	}
}

func TestStartTransfer_RecipientPartyValidation(t *testing.T) {
	// The test envelope (Ed25519) is addressed to EBL2 (sender=EBL1, recipient=EBL2)
	testEnvelopePath := "../testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"

	tests := []struct {
		name             string
		envelopePath     string
		setupParties     func(t *testing.T, env *testEnv)
		expectedStatus   int
		expectedResponse pint.ResponseCode
		wantErrContains  string
	}{
		{
			name:           "accepts when recipient party exists",
			envelopePath:   testEnvelopePath,
			setupParties:   createValidParties,
			expectedStatus: http.StatusCreated,
		},
		{
			name:             "returns BENV when recipient party not found",
			envelopePath:     testEnvelopePath,
			setupParties:     func(t *testing.T, testEnv *testEnv) {}, // no parties
			expectedStatus:   http.StatusUnprocessableEntity,
			expectedResponse: pint.ResponseCodeBENV,
			wantErrContains:  "could not be located using the provided identifying codes",
		},
		{
			name:             "returns BENV when recipient codes resolve to different parties",
			envelopePath:     testEnvelopePath,
			setupParties:     createInvalidParties,
			expectedStatus:   http.StatusUnprocessableEntity,
			expectedResponse: pint.ResponseCodeBENV,
			wantErrContains:  "resolved to multiple different parties",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start server as EBL2
			env := startInProcessServer(t, "EBL2")
			defer env.shutdown()

			// setup parties
			tt.setupParties(t, env)

			envelopesURL := env.baseURL + "/v3/envelopes"

			// Load and POST the envelope
			envelopeData, err := os.ReadFile(tt.envelopePath)
			if err != nil {
				t.Fatalf("Failed to read test envelope: %v", err)
			}

			resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
			if err != nil {
				t.Fatalf("Failed to POST envelope: %v", err)
			}
			defer resp.Body.Close()

			// Verify status code
			if resp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.expectedStatus == http.StatusUnprocessableEntity {
				// Read the signed error response
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)

				// Decode the JWS payload
				payload := decodeSignedFinishedResponse(t, signedResponse)

				// Verify the response code is BENV
				if payload.ResponseCode != tt.expectedResponse {
					t.Errorf("Expected responseCode %q, got %q", tt.expectedResponse, payload.ResponseCode)
				}

				// Verify the reason contains expected error
				if payload.Reason == nil || !strings.Contains(*payload.Reason, tt.wantErrContains) {
					t.Errorf("Expected reason to contain %q, got %v", tt.wantErrContains, payload.Reason)
				}

				// Verify lastEnvelopeTransferChainEntrySignedContentChecksum is set
				if payload.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
					t.Error("Expected lastEnvelopeTransferChainEntrySignedContentChecksum to be set")
				}
			}
		})
	}
}

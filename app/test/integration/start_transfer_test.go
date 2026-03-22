//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

// TestStartTransfer does an end-2-end test of the POST /v3/envelopes endpointd
func TestStartTransfer(t *testing.T) {
	testEnv := startInProcessServer(t, "EBL2", crypto.TrustLevelDV)
	defer testEnv.shutdown()
	createPartiesFromFile(t, testEnv, "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json")

	envelopesURL := testEnv.baseURL + "/v3/envelopes"
	// the test envelope with additional documents (1 ebl visualization, 2 supporting documents)
	testEnvelopeWithDocsPath := "../testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"

	// test envelope with no additional documents
	testEnvelopeNoDocsPath := "../testdata/pint-transfers/HHL71800000-ebl-envelope-nodocs-ed25519.json"

	testTransferChainEntryPath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"

	// signing key is ed25519
	signingKeyPath := "../testdata/keys/private/ed25519-eblplatform.example.com.private.jwk"

	signingKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile(signingKeyPath)
	if err != nil {
		t.Fatalf("Failed to read signing key: %v", err)
	}
	// get the public key for verification

	publicKey := signingKey.Public().(ed25519.PublicKey)

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
				// needed to pass the party validation
				_, _ = createPartiesFromFile(t, testEnv, testTransferChainEntryPath)
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

			expectedTransportDocChecksum, err := ebl.TransportDocument(testEnvelope["transportDocument"]).Checksum()
			if err != nil {
				t.Fatalf("Failed to compute transport document checksum: %v", err)
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

			// get the payload from the JWS string
			// decode the payload from the JWS string
			payloadBytes, err := crypto.VerifyJWSEd25519(lastChainEntryJWS, publicKey)
			if err != nil {
				t.Fatalf("Failed to decode last chain entry: %v", err)
			}

			// cannoicalize and hash the payload to get the expected checksum
			canonicalPayload, err := crypto.CanonicalizeJSON(payloadBytes)
			if err != nil {
				t.Fatalf("Failed to canonicalize last chain entry: %v", err)
			}
			expectedLastChainChecksum, err := crypto.Hash(canonicalPayload)
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
				received := 0
				if payload.ReceivedAdditionalDocumentChecksums != nil {
					received = len(*payload.ReceivedAdditionalDocumentChecksums)
				}
				if received != test.expectedReceivedDocs {
					t.Errorf("Expected %d received additional documents, got %d", test.expectedReceivedDocs, len(*payload.ReceivedAdditionalDocumentChecksums))
				}
				t.Logf("transfer accepted with 200/%v response", payload.ResponseCode)

				// get the envelope reference from the last transfer chain entry checksum (the response does not contain the envelope reference)
				envelope, err := testEnv.queries.GetEnvelopeByLastChainEntrySignedContentPayloadChecksum(ctx, expectedLastChainChecksum)
				if err != nil {
					t.Fatalf("Failed to retrieve envelope from database: %v", err)
				}

				if envelope.ID == uuid.Nil {
					t.Fatalf("Expected envelope reference to be set")
				}

				// Verify transfer is complete (no missing documents)
				missingDocs, err := testEnv.queries.GetMissingAdditionalDocumentChecksums(ctx, envelope.ID)
				if err != nil {
					t.Fatalf("Failed to check missing documents: %v", err)
				}
				if len(missingDocs) != 0 {
					t.Errorf("Expected no missing documents (immediate accept), got %d", len(missingDocs))
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
				// walk backwards through the chain and verify the previous entry checksums
				for i := len(chainEntries) - 1; i > 0; i-- {
					if chainEntries[i].PreviousSignedContentChecksum == nil {
						t.Errorf("Expected previous entry checksum to be set for entry %d", i)
					} else {
						if *chainEntries[i].PreviousSignedContentChecksum != chainEntries[i-1].SignedContentChecksum {
							t.Errorf("Previous entry checksum mismatch for entry %d: expected %s, got %s", i, chainEntries[i-1].SignedContentChecksum, *chainEntries[i].PreviousSignedContentChecksum)
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
				if parsedResponse.TransportDocumentChecksum != ebl.TransportDocumentChecksum(expectedTransportDocChecksum) {
					t.Errorf("TransportDocumentChecksum mismatch:\n  expected: %s\n  got:      %s",
						expectedTransportDocChecksum, parsedResponse.TransportDocumentChecksum)
				}

				// check we can find the envelope by the last chain entry payload checksum on the database
				envelope, err := testEnv.queries.GetEnvelopeByLastChainEntrySignedContentPayloadChecksum(ctx, expectedLastChainChecksum)
				if err != nil {
					t.Fatalf("Failed to retrieve envelope from database: %v", err)
				}
				if parsedResponse.LastEnvelopeTransferChainEntrySignedContentChecksum != ebl.TransferChainEntrySignedContentChecksum(envelope.LastTransferChainEntrySignedContentChecksum) {
					t.Errorf("LastEnvelopeTransferChainEntrySignedContentChecksum mismatch:\n  expected: %s\n  but database has:      %s",
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

				if envelope.ID != envelopeRef {
					t.Errorf("Expected envelope reference to match database record: expected %s, got %s",
						envelopeRef, envelope.ID)
				}

				if envelope.TransportDocumentChecksum != string(ebl.TransportDocumentChecksum(parsedResponse.TransportDocumentChecksum)) {
					t.Errorf("Database checksum mismatch: expected %s, got %s",
						parsedResponse.TransportDocumentChecksum, envelope.TransportDocumentChecksum)
				}

				// Verify envelope is pending (has missing documents)
				missingDocs, err := testEnv.queries.GetMissingAdditionalDocumentChecksums(ctx, envelope.ID)
				if err != nil {
					t.Fatalf("Failed to check missing documents: %v", err)
				}
				if len(missingDocs) == 0 {
					t.Errorf("Expected missing documents (pending transfer), got none")
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
				// walk backwards through the chain and verify the previous entry checksums
				for i := len(chainEntries) - 1; i > 0; i-- {
					if chainEntries[i].PreviousSignedContentChecksum == nil {
						t.Errorf("Expected previous entry checksum to be set for entry %d", i)
					} else {
						if *chainEntries[i].PreviousSignedContentChecksum != chainEntries[i-1].SignedContentChecksum {
							t.Errorf("Previous entry checksum mismatch for entry %d: expected %s, got %s", i, chainEntries[i-1].SignedContentChecksum, *chainEntries[i].PreviousSignedContentChecksum)
						}
					}
				}

				if len(chainEntries) == 0 {
					t.Error("Expected transfer chain entries to be stored")
				}

				// Verify the response checksum matches what's stored in the database
				if parsedResponse.LastEnvelopeTransferChainEntrySignedContentChecksum != ebl.TransferChainEntrySignedContentChecksum(envelope.LastTransferChainEntrySignedContentChecksum) {
					t.Errorf("Expected lastEnvelopeTransferChainEntrySignedContentChecksum to match database value: expected %s, got %s",
						envelope.LastTransferChainEntrySignedContentChecksum, parsedResponse.LastEnvelopeTransferChainEntrySignedContentChecksum)
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
	testTransferChainEntryPath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"

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
			env := startInProcessServer(t, tt.serverPlatform, crypto.TrustLevelDV)
			defer env.shutdown()
			createPartiesFromFile(t, env, testTransferChainEntryPath)

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

// TestStartTransfer_RecipientPartyValidation covers that the start-transfer endpoint rejects envelopes addressed to unknown or untrusted recipient platforms.
func TestStartTransfer_RecipientPartyValidation(t *testing.T) {
	// The test envelope (Ed25519) is addressed to EBL2 (sender=EBL1, recipient=EBL2)
	testEnvelopePath := "../testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"
	testTransferChainEntryPath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"

	tests := []struct {
		name             string
		envelopePath     string
		setupParties     func(t *testing.T, env *testEnv)
		expectedStatus   int
		expectedResponse pint.ResponseCode
		wantErrContains  string
	}{
		{
			name:         "accepts when recipient party exists",
			envelopePath: testEnvelopePath,
			setupParties: func(t *testing.T, testEnv *testEnv) {
				_, _ = createPartiesFromFile(t, testEnv, testTransferChainEntryPath)
			},
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
		// clean db
		t.Run(tt.name, func(t *testing.T) {
			// Start server as EBL2
			env := startInProcessServer(t, "EBL2", crypto.TrustLevelDV)
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

// test for runtime detection of errors that relate to the lifecycle of the ebl:
// - DISE (contradictory transfer chain)
// - actions on surrendered eBLs
func TestTransferLifecycle(t *testing.T) {

	// signing keys
	car1PrivateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../testdata/keys/private/ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}
	ebl1PrivateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../testdata/keys/private/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	ebl2PrivateKey, err := crypto.ReadRSAPrivateKeyFromJWKFile("../testdata/keys/private/rsa-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	// create party structures
	car1Actor, err := ebl.NewActorPartyBuilder("car1 party", "CAR1").
		WithIdentifyingCode("CAR1", "carrier1party@carrier1.example.com", nil).
		Build()
	if err != nil {
		t.Fatalf("could not build actor party %v", err)
	}

	car1Recipient, err := ebl.NewRecipientPartyBuilder("car1 party", "CAR1").
		WithIdentifyingCode("CAR1", "carrier1party@carrier1.example.com", nil).
		Build()
	if err != nil {
		t.Fatalf("could not build recipient party %v", err)
	}

	ebl1Actor, err := ebl.NewActorPartyBuilder("ebl1 party", "EBL1").
		WithIdentifyingCode("EBL1", "ebl1-party@ebl1.example.com", nil).
		Build()
	if err != nil {
		t.Fatalf("could not build actor party %v", err)
	}

	ebl1Recipient, err := ebl.NewRecipientPartyBuilder("ebl1 party", "EBL1").
		WithIdentifyingCode("EBL1", "ebl1-party@ebl1.example.com", nil).
		Build()
	if err != nil {
		t.Fatalf("could not build recipient party %v", err)
	}

	ebl2Actor, err := ebl.NewActorPartyBuilder("ebl2 party", "EBL2").
		WithIdentifyingCode("EBL2", "ebl2-party@ebl2.example.com", nil).
		Build()
	if err != nil {
		t.Fatalf("could not build actor party %v", err)
	}

	ebl2Recipient, err := ebl.NewRecipientPartyBuilder("ebl2 party", "EBL2").
		WithIdentifyingCode("EBL2", "ebl2-party@ebl2.example.com", nil).
		Build()
	if err != nil {
		t.Fatalf("could not build recipient party %v", err)
	}

	// start serveors
	car1env := startInProcessServer(t, "CAR1", crypto.TrustLevelNoX5C)
	ebl1env := startInProcessServer(t, "EBL1", crypto.TrustLevelNoX5C)
	ebl2env := startInProcessServer(t, "EBL2", crypto.TrustLevelNoX5C)

	// set up parties data
	for _, env := range []*testEnv{car1env, ebl1env, ebl2env} {
		defer env.shutdown()
		createTestParty(t, env.queries, car1Actor.PartyName, true, car1Actor.IdentifyingCodes)
		createTestParty(t, env.queries, ebl1Actor.PartyName, true, ebl1Actor.IdentifyingCodes)
		createTestParty(t, env.queries, ebl2Actor.PartyName, true, ebl2Actor.IdentifyingCodes)
	}

	// transport document
	transportDocument := ebl.TransportDocument([]byte(`{"transportDocumentReference":"test_tansport_doc","isToOrder":true}`))

	transportDocumentChecksum, err := transportDocument.Checksum()
	if err != nil {
		t.Fatalf("Failed to compute transport document checksum: %v", err)
	}

	// issuance manifest
	issueToChecksum := ebl.IssueToChecksum("583c29ab3e47f2d80899993200d3fbadb9f8a367f3a39f715935c46d7a283006")

	iBuilder := ebl.NewIssuanceManifestBuilder().
		WithDocumentChecksum(transportDocumentChecksum).
		WithIssueToChecksum(issueToChecksum)

	issuanceManifest, err := iBuilder.Build()
	if err != nil {
		t.Fatalf("could not create issuance manifest %v", err)
	}

	issuanceManifestJWS, err := issuanceManifest.Sign(car1PrivateKey, nil)
	if err != nil {
		t.Fatal("could not sign issuance manifest")
	}

	issuanceTransaction := ebl.CreateIssueTransaction(car1Actor, ebl1Recipient, time.Time{})

	issuanceEntryBuilder := ebl.NewEnvelopeTransferChainEntryBuilder(true).
		WithTransportDocumentChecksum(transportDocumentChecksum).
		WithEBLPlatform("CAR1").
		WithIssuanceManifestSignedContent(issuanceManifestJWS).
		WithTransaction(issuanceTransaction)

	issuanceEntry, err := issuanceEntryBuilder.Build()
	if err != nil {
		t.Fatalf("could not build issuance entry %v", err)
	}

	issuanceEntryJWS, err := issuanceEntry.Sign(car1PrivateKey, nil)
	if err != nil {
		t.Fatal("could not sign issuance entry")
	}

	//  build and sign the envelope manifest, then assemble the full envelope
	mBuilder := ebl.NewEnvelopeManifestBuilder().
		WithTransportDocument(transportDocument).
		WithLastTransferChainEntry(issuanceEntryJWS)
	envelopeManifest, err := mBuilder.Build()
	if err != nil {
		t.Fatal("could not build envelope manifest")
	}

	envelopeManifestJWS, err := envelopeManifest.Sign(car1PrivateKey, nil)
	if err != nil {
		t.Fatal("could not sign envelope manifest")
	}

	eBuilder := ebl.NewEnvelopeBuilder()

	eBuilder.WithTransportDocument(transportDocument).
		WithEnvelopeManifestSignedContent(envelopeManifestJWS).
		AddTransferChainEntry(issuanceEntryJWS)
	envelope, err := eBuilder.Build()
	if err != nil {
		t.Fatalf("could not build envelope %v", err)
	}

	// post issuance envelope to ebl1
	envelopesURL := ebl1env.baseURL + "/v3/envelopes"
	envelopeData, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to marshal envelope: %v", err)
	}

	resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
	if err != nil {
		t.Fatalf("Failed to POST envelope: %v", err)
	}
	defer resp.Body.Close()

	// create a transfer transaction from ebl1 to ebl2
	transferTransaction := ebl.CreateTransferTransaction(ebl1Actor, ebl2Recipient, time.Time{})

	envelopeEbl1ToEbl2, err := ebl.CreateEnvelopeForDelivery(
		ebl.CreateEnvelopeInput{
			ReceivedEnvelope: envelope,
			NewTransactions:  []ebl.Transaction{transferTransaction},
		},
		ebl1PrivateKey,
		nil,
		"EBL1",
	)

	// post the transfer to ebl2
	envelopesURL = ebl2env.baseURL + "/v3/envelopes"
	envelopeData, err = json.Marshal(envelopeEbl1ToEbl2)
	if err != nil {
		t.Fatalf("Failed to marshal envelope: %v", err)
	}
	resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
	if err != nil {
		t.Fatalf("Failed to POST envelope: %v", err)
	}
	defer resp.Body.Close()

	// create a new transfer transaction to transfer from ebl2 back to ebl1
	transferTransaction = ebl.CreateTransferTransaction(ebl2Actor, ebl1Recipient, time.Time{})
	envelopeReturnFromEbl2ToEbl1, err := ebl.CreateEnvelopeForDelivery(
		ebl.CreateEnvelopeInput{
			ReceivedEnvelope: envelopeEbl1ToEbl2,
			NewTransactions:  []ebl.Transaction{transferTransaction},
		},
		ebl2PrivateKey,
		nil,
		"EBL2",
	)
	if err != nil {
		t.Fatalf("Failed to create envelope: %v", err)
	}
	// send from ebl2 back to ebl1
	envelopesURL = ebl1env.baseURL + "/v3/envelopes"
	envelopeData, err = json.Marshal(envelopeReturnFromEbl2ToEbl1)
	if err != nil {
		t.Fatalf("Failed to marshal envelope: %v", err)
	}
	resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
	if err != nil {
		t.Fatalf("Failed to POST envelope: %v", err)
	}
	defer resp.Body.Close()

	// ebl1 is now in possession (car1 issued to ebl1 / ebl1 > ebl2 / ebl2 > ebl1)
	t.Run("DISE - resending a shorter, but legit, chain to a server should fail with DISE", func(t *testing.T) {
		// resend the original envelope to ebl1 - this should trigger DISE since, although the chain is valid, it is shorter than the one currently stored.
		envelopesURL = ebl1env.baseURL + "/v3/envelopes"
		envelopeData, err = json.Marshal(envelope)
		if err != nil {
			t.Fatalf("Failed to marshal envelope: %v", err)
		}
		resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
		if err != nil {
			t.Fatalf("Failed to POST envelope: %v", err)
		}
		if resp.StatusCode != 409 {
			t.Fatalf("Expected status code 409, got %d", resp.StatusCode)
		}
		// check reason contains "new chain is shorter"
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)
		payload := decodeSignedFinishedResponse(t, signedResponse)
		if !strings.Contains(*payload.Reason, "new chain is shorter") {
			t.Errorf("Expected reason to contain 'new chain is shorter', got %q", *payload.Reason)
		}
		defer resp.Body.Close()
	})

	t.Run("DISE - resending a chain with a forked chain should fail with DISE", func(t *testing.T) {
		// send the original envelope again to ebl2 but with a new transfer transaction (DISE error)
		// this is a type of (unlikely) double spend where the receiver ignores the second transfer and uses the first one to
		// try and restart the chain
		transferTransaction = ebl.CreateTransferTransaction(ebl1Actor, ebl2Recipient, time.Time{})
		envelopeConflictEbl1ToEbl2, err := ebl.CreateEnvelopeForDelivery(
			ebl.CreateEnvelopeInput{
				ReceivedEnvelope: envelope,
				NewTransactions:  []ebl.Transaction{transferTransaction},
			},
			ebl1PrivateKey,
			nil,
			"EBL1",
		)
		if err != nil {
			t.Fatalf("Failed to create envelope: %v", err)
		}
		envelopesURL = ebl2env.baseURL + "/v3/envelopes"
		envelopeData, err = json.Marshal(envelopeConflictEbl1ToEbl2)
		if err != nil {
			t.Fatalf("Failed to marshal envelope: %v", err)
		}
		resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
		if err != nil {
			t.Fatalf("Failed to POST envelope: %v", err)
		}
		if resp.StatusCode != 409 {
			t.Fatalf("Expected status code 409, got %d", resp.StatusCode)
		}
		// check reason contains "new chain is shorter"
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)
		payload := decodeSignedFinishedResponse(t, signedResponse)
		if !strings.Contains(*payload.Reason, "payload checksum of incoming chain is different to the stored chain") {
			t.Errorf("Expected reason to contain 'payload checksum of incoming chain is different to the stored chain', got %q", *payload.Reason)
		}
		defer resp.Body.Close()
	})

	envelopeEbl1BlankEndorse := &ebl.Envelope{}
	// blank endorse a transaction from ebl1 to ebl2 (not allowed - blank endorse must be on the same platform)
	t.Run(" sending a BLANK_ENDORSE transaction from ebl1 to ebl2 should be rejected", func(t *testing.T) {
		// note no recipient
		signTransaction := ebl.CreateSignTransaction(ebl1Actor, time.Time{})
		envelopeEbl1BlankEndorse, err = ebl.CreateEnvelopeForDelivery(
			ebl.CreateEnvelopeInput{
				ReceivedEnvelope: envelopeReturnFromEbl2ToEbl1,
				NewTransactions:  []ebl.Transaction{signTransaction},
			},
			ebl1PrivateKey,
			nil,
			"EBL1",
		)
		if err != nil {
			t.Fatalf("Failed to create envelope: %v", err)
		}
		envelopesURL = ebl2env.baseURL + "/v3/envelopes"
		envelopeData, err = json.Marshal(envelopeEbl1BlankEndorse)
		if err != nil {
			t.Fatalf("Failed to marshal envelope: %v", err)
		}
		resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
		if err != nil {
			t.Fatalf("Failed to POST envelope: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 422 {
			t.Fatalf("Expected status code 422, got %d", resp.StatusCode)
		}

		// extract reason
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)
		payload := decodeSignedFinishedResponse(t, signedResponse)
		if !strings.Contains(*payload.Reason, "the envelope is addressed to platform EBL1 but this platform is EBL2") {
			t.Errorf("Expected reason to contain 'the envelope is addressed to platform EBL1 but this platform is EBL2', got %q", *payload.Reason)
		}
	})

	// sign actions must be done on the platform of the ebl possessor - ebl2 should reject this because it will
	// the last transaction (sign) is not addressed to it.   In production it does not make sense to try and send such an envelope.
	t.Run("SIGN - sending a SIGN transaction from ebl1 to ebl2 should be rejected", func(t *testing.T) {
		// note no recipient
		signTransaction := ebl.CreateSignTransaction(ebl1Actor, time.Time{})
		envelopeEbl1Signed, err := ebl.CreateEnvelopeForDelivery(
			ebl.CreateEnvelopeInput{
				ReceivedEnvelope: envelopeEbl1ToEbl2,
				NewTransactions:  []ebl.Transaction{signTransaction},
			},
			ebl1PrivateKey,
			nil,
			"EBL1",
		)
		if err != nil {
			t.Fatalf("Failed to create envelope: %v", err)
		}
		envelopesURL = ebl2env.baseURL + "/v3/envelopes"
		envelopeData, err = json.Marshal(envelopeEbl1Signed)
		if err != nil {
			t.Fatalf("Failed to marshal envelope: %v", err)
		}
		resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
		if err != nil {
			t.Fatalf("Failed to POST envelope: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 422 {
			t.Fatalf("Expected status code 422, got %d", resp.StatusCode)
		}
		// extract reason
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)
		payload := decodeSignedFinishedResponse(t, signedResponse)

		if payload.Reason == nil {
			t.Fatalf("Expected reason to be set")
		}

		if !strings.Contains(*payload.Reason, "entry 2 was created by platform EBL1 but the last transaction in entry 1 was addressed to platform EBL2") {
			t.Errorf("Expected reason to contain 'entry 2 was created by platform EBL1 but the last transaction in entry 1 was addressed to platform EBL2', got %q", *payload.Reason)
		}

	})

	envelopeSurrenderRequestEbl1toCar1 := &ebl.Envelope{}
	t.Run("SurrenderForDelivery - sending a SurrenderForDelivery transaction from ebl1 to car1 should be accepted", func(t *testing.T) {
		surrenderForDeliveryTransaction := ebl.CreateSurrenderForDeliveryTransaction(ebl1Actor, car1Recipient, time.Time{})
		envelopeSurrenderRequestEbl1toCar1, err = ebl.CreateEnvelopeForDelivery(
			ebl.CreateEnvelopeInput{
				ReceivedEnvelope: envelopeReturnFromEbl2ToEbl1,
				NewTransactions:  []ebl.Transaction{surrenderForDeliveryTransaction},
			},
			ebl1PrivateKey,
			nil,
			"EBL1",
		)
		if err != nil {
			t.Fatalf("Failed to create envelope: %v", err)
		}
		envelopesURL = car1env.baseURL + "/v3/envelopes"
		envelopeData, err = json.Marshal(envelopeSurrenderRequestEbl1toCar1)
		if err != nil {
			t.Fatalf("Failed to marshal envelope: %v", err)
		}
		resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
		if err != nil {
			t.Fatalf("Failed to POST envelope: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
		}
	})

	// SACC - SACC from car1 to ebl2 should be accepted
	envelopeSACCfromCar1ToEbl1 := &ebl.Envelope{}
	t.Run("SACC - sending a SACC transaction from car1 to ebl1 should be accepted", func(t *testing.T) {
		saccTransaction := ebl.CreateSACCTransaction(car1Actor, ebl1Recipient, time.Time{})
		envelopeSACCfromCar1ToEbl1, err = ebl.CreateEnvelopeForDelivery(
			ebl.CreateEnvelopeInput{
				ReceivedEnvelope: envelopeSurrenderRequestEbl1toCar1,
				NewTransactions:  []ebl.Transaction{saccTransaction},
			},
			car1PrivateKey,
			nil,
			"CAR1",
		)
		if err != nil {
			t.Fatalf("Failed to create envelope: %v", err)
		}
		envelopesURL = ebl1env.baseURL + "/v3/envelopes"
		envelopeData, err = json.Marshal(envelopeSACCfromCar1ToEbl1)
		if err != nil {
			t.Fatalf("Failed to marshal envelope: %v", err)
		}
		resp, err = http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
		if err != nil {
			t.Fatalf("Failed to POST envelope: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
		}

	})
}

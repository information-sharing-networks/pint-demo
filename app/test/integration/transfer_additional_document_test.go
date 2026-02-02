//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

var (
	// test envelope
	testEnvelopeWithDocsPath = "../../internal/crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"
	// unsigned manifest (the signed version is in the test envelope - read it here for convenient access to doc checksums)
	testEnvelopeManifest = "../../internal/crypto/testdata/pint-transfers/HHL71800000-envelope-manifest-ed25519.json"

	//expectedTotalDocs := 3 // the test envelope has 1 ebl visualization and 2 supporting documents
	eblVisualizationPath = "../../internal/crypto/testdata/transport-documents/HHL71800000.pdf"
	invoicePath          = "../../internal/crypto/testdata/pint-transfers/HHL71800000-invoice.pdf"
	packingListPath      = "../../internal/crypto/testdata/pint-transfers/HHL71800000-packing-list.pdf"
)

type additionalDocumentsState struct {
	missingDocs  []string
	receivedDocs []string
	responseCode *pint.ResponseCode // nil for 201 Created (pending), non-nil for 200 OK (RECE/DUPE)
}

// use the /envelopes endpoint on a previously started transfer to get the current status
// returns the missing additional document checksums, and the received additional document checksums
// errors in here are all t.Fatal()
func getAdditionalDocumentsState(t *testing.T, baseURL string, envelopePath string) additionalDocumentsState {
	t.Helper()

	envelopeData, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("Failed to read test envelope: %v", err)
	}

	envelopesURL := baseURL + "/v3/envelopes"
	resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
	if err != nil {
		t.Fatalf("Failed to POST envelope: %v", err)
	}
	defer resp.Body.Close()

	// Per DCSA spec:
	// - 201 Created (unsigned): Transfer pending, documents still needed
	// - 200 OK (signed): Transfer accepted (RECE) or duplicate of accepted (DUPE)
	if resp.StatusCode == http.StatusCreated {
		// Pending transfer - decode unsigned EnvelopeTransferStartedResponse
		var startedResponse pint.EnvelopeTransferStartedResponse
		if err := json.NewDecoder(resp.Body).Decode(&startedResponse); err != nil {
			t.Fatalf("Failed to decode 201 response: %v", err)
		}

		return additionalDocumentsState{
			missingDocs:  startedResponse.MissingAdditionalDocumentChecksums,
			receivedDocs: []string{}, // No received docs list in 201 response
			responseCode: nil,        // No response code for pending transfers
		}
	}

	if resp.StatusCode == http.StatusOK {
		// Accepted or duplicate - decode signed EnvelopeTransferFinishedResponse
		var parsedResponse pint.SignedEnvelopeTransferFinishedResponse
		if err := json.NewDecoder(resp.Body).Decode(&parsedResponse); err != nil {
			t.Fatalf("Failed to decode 200 response: %v", err)
		}

		payload := decodeSignedFinishedResponse(t, parsedResponse)

		return additionalDocumentsState{
			missingDocs:  payload.MissingAdditionalDocumentChecksums,
			receivedDocs: payload.ReceivedAdditionalDocumentChecksums,
			responseCode: &payload.ResponseCode,
		}
	}

	t.Fatalf("Expected status 200 or 201, got %d", resp.StatusCode)
	return additionalDocumentsState{}
}

// TestTransferAdditionalDocument_SequentialUploads tests the sequential upload of documents
// in the order: EBL, duplicate EBL, invoice, duplicate invoice, packing list
// note don't run the subtests individually since they rely on the previous state
func TestTransferAdditionalDocument_SequentialUploads(t *testing.T) {
	ctx := context.Background()
	testDB := setupCleanDatabase(t, ctx)
	testEnv := setupTestEnvironment(testDB)
	testDatabaseURL := getDatabaseURL()
	baseURL, stopServer := startInProcessServer(t, ctx, testEnv.dbConn, testDatabaseURL)
	envelopesURL := baseURL + "/v3/envelopes"
	defer stopServer()

	// Load test envelope and manifest
	envelopeData, err := os.ReadFile(testEnvelopeWithDocsPath)
	if err != nil {
		t.Fatalf("Failed to read test envelope: %v", err)
	}

	manifestData, err := os.ReadFile(testEnvelopeManifest)
	if err != nil {
		t.Fatalf("Failed to read test envelope manifest: %v", err)
	}

	envelopeManifest := &ebl.EnvelopeManifest{}
	if err := json.Unmarshal(manifestData, envelopeManifest); err != nil {
		t.Fatalf("Failed to parse envelope manifest: %v", err)
	}

	eblVisualizationChecksum := envelopeManifest.EBLVisualisationByCarrier.DocumentChecksum
	invoiceChecksum := envelopeManifest.SupportingDocuments[0].DocumentChecksum
	packingListChecksum := envelopeManifest.SupportingDocuments[1].DocumentChecksum

	// POST the envelope to start the transfer
	resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
	if err != nil {
		t.Fatalf("Failed to POST envelope: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", resp.StatusCode)
	}

	var startResponse pint.EnvelopeTransferStartedResponse
	if err := json.NewDecoder(resp.Body).Decode(&startResponse); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	envelopeRef := startResponse.EnvelopeReference
	envelopeUUID, _ := uuid.Parse(envelopeRef)
	t.Logf("Started transfer with envelope reference: %s", envelopeRef)

	// Load the actual PDF files
	eblVisualizationContent, err := os.ReadFile(eblVisualizationPath)
	if err != nil {
		t.Fatalf("Failed to read eBL visualization: %v", err)
	}

	invoiceContent, err := os.ReadFile(invoicePath)
	if err != nil {
		t.Fatalf("Failed to read invoice: %v", err)
	}

	packingListContent, err := os.ReadFile(packingListPath)
	if err != nil {
		t.Fatalf("Failed to read packing list: %v", err)
	}

	// Define test cases in sequence
	tests := []struct {
		name                 string
		documentChecksum     string
		documentContent      []byte
		isEblVisualization   bool
		isDuplicate          bool
		expectedMissingCount int
	}{
		{
			name:                 "1. Upload EBL visualization",
			documentChecksum:     eblVisualizationChecksum,
			documentContent:      eblVisualizationContent,
			isEblVisualization:   true,
			isDuplicate:          false,
			expectedMissingCount: 2,
		},
		{
			name:                 "2. Re-upload EBL visualization (duplicate)",
			documentChecksum:     eblVisualizationChecksum,
			documentContent:      eblVisualizationContent,
			isEblVisualization:   true,
			isDuplicate:          true,
			expectedMissingCount: 2,
		},
		{
			name:                 "3. Upload invoice",
			documentChecksum:     invoiceChecksum,
			documentContent:      invoiceContent,
			isEblVisualization:   false,
			isDuplicate:          false,
			expectedMissingCount: 1,
		},
		{
			name:                 "4. Re-upload invoice (duplicate)",
			documentChecksum:     invoiceChecksum,
			documentContent:      invoiceContent,
			isEblVisualization:   false,
			isDuplicate:          true,
			expectedMissingCount: 1,
		},
		{
			name:                 "5. Upload packing list (all docs uploaded)",
			documentChecksum:     packingListChecksum,
			documentContent:      packingListContent,
			isEblVisualization:   false,
			isDuplicate:          false,
			expectedMissingCount: 0, // all documents received
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Upload the document
			url := baseURL + "/v3/envelopes/" + envelopeRef + "/additional-documents/" + tt.documentChecksum
			base64Content := base64.StdEncoding.EncodeToString(tt.documentContent)

			req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader([]byte(base64Content)))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to PUT document: %v", err)
			}
			defer resp.Body.Close()

			// Verify HTTP status
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("Expected status 204, got %d", resp.StatusCode)
			}

			// Verify the document was stored in the database (skip for duplicates)
			if !tt.isDuplicate {
				doc, err := testEnv.queries.GetAdditionalDocument(ctx, database.GetAdditionalDocumentParams{
					EnvelopeID:       envelopeUUID,
					DocumentChecksum: tt.documentChecksum,
				})
				if err != nil {
					t.Fatalf("Failed to retrieve document from database: %v", err)
				}

				if doc.IsEblVisualisation != tt.isEblVisualization {
					t.Fatalf("Expected IsEblVisualisation=%v, got %v", tt.isEblVisualization, doc.IsEblVisualisation)
				}
				if !doc.ReceivedAt.Valid {
					t.Fatalf("Expected document to be marked as received")
				}
				if !bytes.Equal(doc.DocumentContent, tt.documentContent) {
					t.Fatalf("Document content mismatch")
				}
			}

			// Check the envelope status by POSTing the envelope again
			state := getAdditionalDocumentsState(t, baseURL, testEnvelopeWithDocsPath)

			if len(state.missingDocs) != tt.expectedMissingCount {
				t.Errorf("Expected %d missing documents, got %d: %v", tt.expectedMissingCount, len(state.missingDocs), state.missingDocs)
			}

			// Verify document is NOT in missing list (it's been uploaded)
			if slices.Contains(state.missingDocs, tt.documentChecksum) {
				t.Errorf("Expected document %s not to be in missing list", tt.documentChecksum)
			}

			t.Logf("✓ %s (missing: %d)", tt.name, len(state.missingDocs))
		})
	}

	// After all documents are uploaded, call finish-transfer endpoint to complete the transfer
	t.Run("6. Finish transfer (expect RECE)", func(t *testing.T) {
		t.Skip("Finish-transfer endpoint not yet implemented")
		finishURL := baseURL + "/v3/envelopes/" + envelopeRef + "/finish-transfer"
		req, err := http.NewRequest(http.MethodPut, finishURL, nil)
		if err != nil {
			t.Fatalf("Failed to create finish-transfer request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to PUT finish-transfer: %v", err)
		}
		defer resp.Body.Close()

		// Verify HTTP status
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		// Decode the signed response
		var signedResp pint.SignedEnvelopeTransferFinishedResponse
		if err := json.NewDecoder(resp.Body).Decode(&signedResp); err != nil {
			t.Fatalf("Failed to decode signed response: %v", err)
		}

		// Decode the JWS payload
		payload := decodeSignedFinishedResponse(t, signedResp)

		// Verify response code is RECE (first acceptance)
		if payload.ResponseCode != pint.ResponseCodeRECE {
			t.Errorf("Expected responseCode 'RECE', got '%s'", payload.ResponseCode)
		}

		// Verify all documents are in received list
		if len(payload.ReceivedAdditionalDocumentChecksums) != 3 {
			t.Errorf("Expected 3 received documents, got %d", len(payload.ReceivedAdditionalDocumentChecksums))
		}

		// Verify no missing documents
		if len(payload.MissingAdditionalDocumentChecksums) != 0 {
			t.Errorf("Expected 0 missing documents, got %d", len(payload.MissingAdditionalDocumentChecksums))
		}

		t.Logf("✓ Transfer finished with RECE response (received: %d)", len(payload.ReceivedAdditionalDocumentChecksums))
	})

	// Retry finish-transfer to verify DUPE response
	t.Run("7. Retry finish transfer (expect DUPE)", func(t *testing.T) {
		t.Skip("Finish-transfer endpoint not yet implemented")
		finishURL := baseURL + "/v3/envelopes/" + envelopeRef + "/finish-transfer"
		req, err := http.NewRequest(http.MethodPut, finishURL, nil)
		if err != nil {
			t.Fatalf("Failed to create finish-transfer request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to PUT finish-transfer: %v", err)
		}
		defer resp.Body.Close()

		// Verify HTTP status
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		// Decode the signed response
		var signedResp pint.SignedEnvelopeTransferFinishedResponse
		if err := json.NewDecoder(resp.Body).Decode(&signedResp); err != nil {
			t.Fatalf("Failed to decode signed response: %v", err)
		}

		// Decode the JWS payload
		payload := decodeSignedFinishedResponse(t, signedResp)

		// Verify response code is DUPE (already accepted)
		if payload.ResponseCode != pint.ResponseCodeDUPE {
			t.Errorf("Expected responseCode 'DUPE', got '%s'", payload.ResponseCode)
		}

		t.Logf("✓ Retry finish-transfer returned DUPE response")
	})
}

// TestTransferAdditionalDocument_ErrorCases tests various error scenarios
// These tests are independent and don't rely on sequential state
func TestTransferAdditionalDocument_ErrorCases(t *testing.T) {
	ctx := context.Background()
	testDB := setupCleanDatabase(t, ctx)
	testEnv := setupTestEnvironment(testDB)
	testDatabaseURL := getDatabaseURL()
	baseURL, stopServer := startInProcessServer(t, ctx, testEnv.dbConn, testDatabaseURL)
	envelopesURL := baseURL + "/v3/envelopes"
	defer stopServer()

	// Load test envelope and manifest
	envelopeData, err := os.ReadFile(testEnvelopeWithDocsPath)
	if err != nil {
		t.Fatalf("Failed to read test envelope: %v", err)
	}

	manifestData, err := os.ReadFile(testEnvelopeManifest)
	if err != nil {
		t.Fatalf("Failed to read test envelope manifest: %v", err)
	}

	envelopeManifest := &ebl.EnvelopeManifest{}
	if err := json.Unmarshal(manifestData, envelopeManifest); err != nil {
		t.Fatalf("Failed to parse envelope manifest: %v", err)
	}

	packingListChecksum := envelopeManifest.SupportingDocuments[1].DocumentChecksum

	// POST the envelope to start the transfer
	resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
	if err != nil {
		t.Fatalf("Failed to POST envelope: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", resp.StatusCode)
	}

	var startResponse pint.EnvelopeTransferStartedResponse
	if err := json.NewDecoder(resp.Body).Decode(&startResponse); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	envelopeRef := startResponse.EnvelopeReference
	t.Logf("Started transfer with envelope reference: %s", envelopeRef)

	// Load document content for tests
	invoiceContent, err := os.ReadFile(invoicePath)
	if err != nil {
		t.Fatalf("Failed to read invoice: %v", err)
	}

	packingListContent, err := os.ReadFile(packingListPath)
	if err != nil {
		t.Fatalf("Failed to read packing list: %v", err)
	}

	// Define error test cases
	tests := []struct {
		name                 string
		envelopeRef          string
		documentChecksum     string
		documentContent      []byte
		expectedStatusCode   int
		expectedResponseCode *pint.ResponseCode // nil for non-PINT error responses
		checkReason          bool
	}{
		{
			name:                 "checksum mismatch returns 409 INCD",
			envelopeRef:          envelopeRef,
			documentChecksum:     packingListChecksum,
			documentContent:      invoiceContent, // Wrong content!
			expectedStatusCode:   http.StatusConflict,
			expectedResponseCode: &[]pint.ResponseCode{pint.ResponseCodeINCD}[0],
			checkReason:          true,
		},
		{
			name:               "invalid base64 returns 400",
			envelopeRef:        envelopeRef,
			documentChecksum:   packingListChecksum,
			documentContent:    []byte("this is not valid base64!!!"),
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:                 "document not in manifest returns 422 BENV",
			envelopeRef:          envelopeRef,
			documentChecksum:     "0000000000000000000000000000000000000000000000000000000000000000",
			documentContent:      []byte("some content"),
			expectedStatusCode:   http.StatusUnprocessableEntity,
			expectedResponseCode: &[]pint.ResponseCode{pint.ResponseCodeBENV}[0],
		},
		{
			name:               "invalid envelope reference returns 400",
			envelopeRef:        uuid.New().String(), // Valid UUID but doesn't exist
			documentChecksum:   packingListChecksum,
			documentContent:    packingListContent,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "malformed envelope reference returns 400",
			envelopeRef:        "not-a-uuid",
			documentChecksum:   packingListChecksum,
			documentContent:    packingListContent,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "empty body returns 400",
			envelopeRef:        envelopeRef,
			documentChecksum:   packingListChecksum,
			documentContent:    []byte(""),
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := baseURL + "/v3/envelopes/" + tt.envelopeRef + "/additional-documents/" + tt.documentChecksum

			// Encode content as base64 unless it's already invalid base64 test
			var body []byte
			if tt.name == "invalid base64 returns 400" {
				body = tt.documentContent
			} else {
				body = []byte(base64.StdEncoding.EncodeToString(tt.documentContent))
			}

			req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to PUT document: %v", err)
			}
			defer resp.Body.Close()

			// Verify HTTP status code
			if resp.StatusCode != tt.expectedStatusCode {
				t.Errorf("Expected status %d, got %d", tt.expectedStatusCode, resp.StatusCode)
			}

			// If we expect a PINT response code, verify it
			if tt.expectedResponseCode != nil {
				var signedResp pint.SignedEnvelopeTransferFinishedResponse
				if err := json.NewDecoder(resp.Body).Decode(&signedResp); err != nil {
					t.Fatalf("Failed to decode signed response: %v", err)
				}

				payload := decodeSignedFinishedResponse(t, signedResp)

				if payload.ResponseCode != *tt.expectedResponseCode {
					t.Errorf("Expected response code %s, got %s", *tt.expectedResponseCode, payload.ResponseCode)
				}

				if tt.checkReason && (payload.Reason == nil || *payload.Reason == "") {
					t.Error("Expected reason to be populated")
				}

				t.Logf("✓ %s (response code: %s)", tt.name, payload.ResponseCode)
			} else {
				// For non-PINT errors, just verify we got an error response
				t.Logf("✓ %s", tt.name)
			}
		})
	}
}

//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
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
	testEnvelopeWithDocsPath = "../testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"
	// unsigned manifest (the signed version is in the test envelope - read it here for convenient access to doc checksums)
	testEnvelopeManifest = "../testdata/pint-transfers/HHL71800000-envelope-manifest-ed25519.json"

	//expectedTotalDocs := 3 // the test envelope has 1 ebl visualization and 2 supporting documents
	eblVisualizationPath = "../testdata/issuance-documents/HHL71800000.pdf"
	invoicePath          = "../testdata/pint-transfers/HHL71800000-invoice.pdf"
	packingListPath      = "../testdata/pint-transfers/HHL71800000-packing-list.pdf"
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
		// Accepted or duplicate - read signed EnvelopeTransferFinishedResponse
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		signedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)

		payload := decodeSignedFinishedResponse(t, signedResponse)

		return additionalDocumentsState{
			missingDocs:  payload.MissingAdditionalDocumentChecksums,
			receivedDocs: *payload.ReceivedAdditionalDocumentChecksums,
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
	testEnv := startInProcessServer(t, "EBL2")
	createValidParties(t, testEnv)
	envelopesURL := testEnv.baseURL + "/v3/envelopes"
	defer testEnv.shutdown()

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
			name:                 "1. uploads EBL visualization",
			documentChecksum:     eblVisualizationChecksum,
			documentContent:      eblVisualizationContent,
			isEblVisualization:   true,
			isDuplicate:          false,
			expectedMissingCount: 2,
		},
		{
			name:                 "2. accepts duplicate EBL visualization",
			documentChecksum:     eblVisualizationChecksum,
			documentContent:      eblVisualizationContent,
			isEblVisualization:   true,
			isDuplicate:          true,
			expectedMissingCount: 2,
		},
		{
			name:                 "3. uploads invoice",
			documentChecksum:     invoiceChecksum,
			documentContent:      invoiceContent,
			isEblVisualization:   false,
			isDuplicate:          false,
			expectedMissingCount: 1,
		},
		{
			name:                 "4. accepts duplicate invoice",
			documentChecksum:     invoiceChecksum,
			documentContent:      invoiceContent,
			isEblVisualization:   false,
			isDuplicate:          true,
			expectedMissingCount: 1,
		},
		{
			name:                 "5. uploads packing list completing transfer",
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
			url := testEnv.baseURL + "/v3/envelopes/" + envelopeRef + "/additional-documents/" + tt.documentChecksum
			base64Content := base64.StdEncoding.EncodeToString(tt.documentContent)

			// use the json package to marshal the base64Content as json string
			jsonContent, err := json.Marshal(base64Content)
			if err != nil {
				t.Fatalf("Failed to marshal base64 content: %v", err)
			}

			req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader([]byte(jsonContent)))
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
			state := getAdditionalDocumentsState(t, testEnv.baseURL, testEnvelopeWithDocsPath)

			if len(state.missingDocs) != tt.expectedMissingCount {
				t.Errorf("Expected %d missing documents, got %d: %v", tt.expectedMissingCount, len(state.missingDocs), state.missingDocs)
			}

			// Verify document is NOT in missing list (it's been uploaded)
			if slices.Contains(state.missingDocs, tt.documentChecksum) {
				t.Errorf("Expected document %s not to be in missing list", tt.documentChecksum)
			}

			t.Logf("%s (missing: %d)", tt.name, len(state.missingDocs))
		})
	}

	// After all documents are uploaded, call finish-transfer endpoint to complete the transfer
	t.Run("6. finishes transfer and returns RECE", func(t *testing.T) {
		finishURL := testEnv.baseURL + "/v3/envelopes/" + envelopeRef + "/finish-transfer"
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

		// Read the signed response
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		SignedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)

		// Decode the JWS payload
		payload := decodeSignedFinishedResponse(t, SignedResponse)

		// Verify response code is RECE (first acceptance)
		if payload.ResponseCode != pint.ResponseCodeRECE {
			t.Errorf("Expected responseCode 'RECE', got '%s'", payload.ResponseCode)
		}

		// Verify all documents are in received list
		if len(*payload.ReceivedAdditionalDocumentChecksums) != 3 {
			t.Errorf("Expected 3 received documents, got %d", len(*payload.ReceivedAdditionalDocumentChecksums))
		}

		// Verify no missing documents
		if len(payload.MissingAdditionalDocumentChecksums) != 0 {
			t.Errorf("Expected 0 missing documents, got %d", len(payload.MissingAdditionalDocumentChecksums))
		}

		t.Logf("Transfer finished with RECE response (received: %d)", len(*payload.ReceivedAdditionalDocumentChecksums))
	})

	// Retry finish-transfer to verify DUPE response
	t.Run("7. retry: returns DUPE on finish transfer", func(t *testing.T) {
		finishURL := testEnv.baseURL + "/v3/envelopes/" + envelopeRef + "/finish-transfer"
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

		// Read the signed response
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		SignedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)

		// Decode the JWS payload
		payload := decodeSignedFinishedResponse(t, SignedResponse)

		// Verify response code is DUPE (already accepted)
		if payload.ResponseCode != pint.ResponseCodeDUPE {
			t.Errorf("Expected responseCode 'DUPE', got '%s'", payload.ResponseCode)
		}

		// Per DCSA spec: DUPE response must include the accepted version of the last
		// EnvelopeTransferChainEntrySignedContent from the previously accepted transfer
		if payload.DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent == nil {
			t.Error("Expected duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent to be set for DUPE response")
		} else if *payload.DuplicateOfAcceptedEnvelopeTransferChainEntrySignedContent == "" {
			t.Error("Expected duplicateOfAcceptedEnvelopeTransferChainEntrySignedContent to be non-empty")
		}

		t.Logf("Retry finish-transfer returned DUPE response with accepted chain entry")
	})
}

// TestTransferAdditionalDocument_ErrorCases tests various error scenarios
// These tests are independent and don't rely on sequential state
func TestTransferAdditionalDocument_ErrorCases(t *testing.T) {
	testEnv := startInProcessServer(t, "EBL2")
	createValidParties(t, testEnv)
	envelopesURL := testEnv.baseURL + "/v3/envelopes"
	defer testEnv.shutdown()

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
		skipEncoding         bool // If true, send raw content
	}{
		{
			name:                 "returns INCD when checksum mismatch",
			envelopeRef:          envelopeRef,
			documentChecksum:     packingListChecksum,
			documentContent:      invoiceContent, // Wrong content!
			expectedStatusCode:   http.StatusConflict,
			expectedResponseCode: &[]pint.ResponseCode{pint.ResponseCodeINCD}[0],
			checkReason:          true,
		},
		{
			name:               "error: invalid request body returns 400",
			envelopeRef:        envelopeRef,
			documentChecksum:   packingListChecksum,
			documentContent:    []byte("!!invalid base64!!"),
			expectedStatusCode: http.StatusBadRequest,
			skipEncoding:       true,
		},
		{
			name:                 "returns INCD when document not in manifest",
			envelopeRef:          envelopeRef,
			documentChecksum:     "0000000000000000000000000000000000000000000000000000000000000000",
			documentContent:      []byte("some content"),
			expectedStatusCode:   http.StatusConflict,
			expectedResponseCode: &[]pint.ResponseCode{pint.ResponseCodeINCD}[0],
		},
		{
			name:               "error: invalid envelope reference returns 400",
			envelopeRef:        uuid.New().String(), // Valid UUID but doesn't exist
			documentChecksum:   packingListChecksum,
			documentContent:    packingListContent,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "error: malformed envelope reference returns 400",
			envelopeRef:        "not-a-uuid",
			documentChecksum:   packingListChecksum,
			documentContent:    packingListContent,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "error: empty body returns 400",
			envelopeRef:        envelopeRef,
			documentChecksum:   packingListChecksum,
			documentContent:    []byte(""),
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := testEnv.baseURL + "/v3/envelopes/" + tt.envelopeRef + "/additional-documents/" + tt.documentChecksum

			// Encode content as base64 unless skipBase64Encoding is set
			var body []byte
			if tt.skipEncoding {
				body = tt.documentContent
			} else {
				b := []byte(base64.StdEncoding.EncodeToString(tt.documentContent))

				// use the json package to marshal the body as json string
				body, err = json.Marshal(b)
				if err != nil {
					t.Fatalf("Failed to marshal body: %v", err)
				}
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
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				SignedResponse := pint.SignedEnvelopeTransferFinishedResponse(bodyBytes)

				payload := decodeSignedFinishedResponse(t, SignedResponse)

				if payload.ResponseCode != *tt.expectedResponseCode {
					t.Errorf("Expected response code %s, got %s", *tt.expectedResponseCode, payload.ResponseCode)
				}

				if tt.checkReason && (payload.Reason == nil || *payload.Reason == "") {
					t.Error("Expected reason to be populated")
				}

				t.Logf("%s (response code: %s)", tt.name, payload.ResponseCode)
			} else {
				// For non-PINT errors, just verify we got an error response
				t.Logf("%s", tt.name)
			}
		})
	}
}

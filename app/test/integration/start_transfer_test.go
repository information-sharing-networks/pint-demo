//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
)

// TestStartTransfer does an end-2-end test of the POST /v3/envelopes endpoint
func TestStartTransfer(t *testing.T) {
	ctx := context.Background()
	testDB := setupTestDatabase(t, ctx)
	testEnv := setupTestEnvironment(testDB)
	testDatabaseURL := getTestDatabaseURL()
	baseURL, stopServer := startInProcessServer(t, ctx, testEnv.dbConn, testDatabaseURL)

	defer stopServer()

	envelopesURL := baseURL + "/v3/envelopes"

	t.Run("valid envelope returns 201 Created", func(t *testing.T) {
		// Load valid test envelope
		envelopeData, err := os.ReadFile("../../internal/crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json")
		if err != nil {
			t.Fatalf("Failed to read test envelope: %v", err)
		}

		// POST the envelope
		resp, err := http.Post(envelopesURL, "application/json", bytes.NewReader(envelopeData))
		if err != nil {
			t.Fatalf("Failed to POST envelope: %v", err)
		}
		defer resp.Body.Close()

		// Verify status code
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 201 or 200, got %d", resp.StatusCode)
		}

		// Verify Content-Type
		contentType := resp.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
		}

		// Parse response
		var response pint.EnvelopeTransferStartedResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response structure
		if response.EnvelopeReference == "" {
			t.Error("Expected envelopeReference to be set")
		}

		if response.TransportDocumentChecksum == "" {
			t.Error("Expected transportDocumentChecksum to be set")
		}

		if len(response.TransportDocumentChecksum) != 64 {
			t.Errorf("Expected transportDocumentChecksum to be 64 hex chars, got %d", len(response.TransportDocumentChecksum))
		}

		if response.LastEnvelopeTransferChainEntrySignedContentChecksum == "" {
			t.Error("Expected lastEnvelopeTransferChainEntrySignedContentChecksum to be set")
		}

		if len(response.LastEnvelopeTransferChainEntrySignedContentChecksum) != 64 {
			t.Errorf("Expected lastEnvelopeTransferChainEntrySignedContentChecksum to be 64 hex chars, got %d", len(response.LastEnvelopeTransferChainEntrySignedContentChecksum))
		}

		// MissingAdditionalDocumentChecksums should be an array (may be empty or populated)
		if response.MissingAdditionalDocumentChecksums == nil {
			t.Error("Expected missingAdditionalDocumentChecksums to be set (even if empty)")
		}

		// Verify database record was created
		envelopeRef, err := uuid.Parse(response.EnvelopeReference)
		if err != nil {
			t.Fatalf("Failed to parse envelope reference UUID: %v", err)
		}

		envelope, err := testEnv.queries.GetEnvelopeByReference(ctx, envelopeRef)
		if err != nil {
			t.Fatalf("Failed to retrieve envelope from database: %v", err)
		}

		if envelope.TransportDocumentChecksum != response.TransportDocumentChecksum {
			t.Errorf("Database checksum mismatch: expected %s, got %s",
				response.TransportDocumentChecksum, envelope.TransportDocumentChecksum)
		}

		if envelope.State != "PENDING" {
			t.Errorf("Expected envelope state 'PENDING', got '%s'", envelope.State)
		}

		// Verify trust level is stored correctly (1 = TrustLevelEVOV)
		if envelope.TrustLevel != 1 {
			t.Errorf("Expected trust level 1 (EV/OV), got %d", envelope.TrustLevel)
		}

		// Verify transfer chain entries were stored
		chainEntries, err := testEnv.queries.ListTransferChainEntries(ctx, envelope.ID)
		if err != nil {
			t.Fatalf("Failed to retrieve transfer chain entries: %v", err)
		}

		if len(chainEntries) == 0 {
			t.Error("Expected transfer chain entries to be stored")
		}

		t.Logf("Envelope created with reference: %s", response.EnvelopeReference)
		t.Logf("Transfer chain entries stored: %d", len(chainEntries))
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

		if len(errorResp.Errors) == 0 {
			t.Error("Expected errors array to be populated")
		}
	})

	t.Run("tampered envelope returns 400 Bad Request", func(t *testing.T) {
		// Load valid test envelope
		envelopeData, err := os.ReadFile("../../internal/crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json")
		if err != nil {
			t.Fatalf("Failed to read test envelope: %v", err)
		}

		// Parse and tamper with the envelope
		var envelope map[string]interface{}
		if err := json.Unmarshal(envelopeData, &envelope); err != nil {
			t.Fatalf("Failed to parse envelope: %v", err)
		}

		// Tamper with the transport document
		envelope["transportDocument"] = map[string]interface{}{
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

		// Should return 400 Bad Request (envelope verification failed)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}

		// Parse error response
		var errorResp pint.ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			t.Fatalf("Failed to decode error response: %v", err)
		}

		if len(errorResp.Errors) == 0 {
			t.Error("Expected errors array to be populated")
		}

	})
}

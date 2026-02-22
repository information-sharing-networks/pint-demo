package ebl

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

var (
	// thse are valid test data for building an envelope manifest (not real JWS strings)
	testTransportDocument = []byte(`{"transportDocumentReference":"MAEU123456","shippingInstructionReference":"SI123456"}`)
)

func TestEnvelopeBuilder(t *testing.T) {
	// mock transfer chain entries (in reality these would be signed JWS strings)
	transferChainEntry1 := EnvelopeTransferChainEntrySignedContent("eyJhbGci...ENTRY_1_JWS")
	transferChainEntry2 := EnvelopeTransferChainEntrySignedContent("eyJhbGci...ENTRY_2_JWS")

	// 3. Create mock envelope manifest signed content (in reality this would be a signed JWS)
	envelopeManifest := EnvelopeManifestSignedContent("eyJhbGci...MANIFEST_JWS")

	// 4. Build the envelope
	envelope, err := NewEnvelopeBuilder().
		WithTransportDocument(testTransportDocument).
		WithEnvelopeManifestSignedContent(envelopeManifest).
		AddTransferChainEntry(transferChainEntry1).
		AddTransferChainEntry(transferChainEntry2).
		Build()

	if err != nil {
		t.Fatalf("Failed to build envelope: %v", err)
	}

	// 5. Validate the envelope
	if err := envelope.ValidateStructure(); err != nil {
		t.Fatalf("Envelope validation failed: %v", err)
	}

	// 6. Verify the structure
	if len(envelope.EnvelopeTransferChain) != 2 {
		t.Errorf("Expected 2 transfer chain entries, got %d", len(envelope.EnvelopeTransferChain))
	}

	if envelope.EnvelopeManifestSignedContent != envelopeManifest {
		t.Errorf("Manifest JWS mismatch")
	}

	// 7. Verify we can serialize to JSON
	_, err = json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to marshal envelope: %v", err)
	}
}

// TestEnvelopeValidation tests validation rules
func TestEnvelopeValidation(t *testing.T) {
	tests := []struct {
		name        string
		envelope    *Envelope
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid envelope",
			envelope: &Envelope{
				TransportDocument:             []byte(`{"test": "data"}`),
				EnvelopeManifestSignedContent: "eyJhbGci...",
				EnvelopeTransferChain:         []EnvelopeTransferChainEntrySignedContent{"eyJhbGci..."},
			},
			expectError: false,
		},
		{
			name: "missing transport document",
			envelope: &Envelope{
				EnvelopeManifestSignedContent: "eyJhbGci...",
				EnvelopeTransferChain:         []EnvelopeTransferChainEntrySignedContent{"eyJhbGci..."},
			},
			expectError: true,
			errorMsg:    "transportDocument is required",
		},
		{
			name: "missing manifest",
			envelope: &Envelope{
				TransportDocument:     []byte(`{"test": "data"}`),
				EnvelopeTransferChain: []EnvelopeTransferChainEntrySignedContent{"eyJhbGci..."},
			},
			expectError: true,
			errorMsg:    "envelopeManifestSignedContent is required",
		},
		{
			name: "empty transfer chain",
			envelope: &Envelope{
				TransportDocument:             []byte(`{"test": "data"}`),
				EnvelopeManifestSignedContent: "eyJhbGci...",
				EnvelopeTransferChain:         []EnvelopeTransferChainEntrySignedContent{},
			},
			expectError: true,
			errorMsg:    "envelopeTransferChain must contain at least one entry",
		},
		{
			name: "invalid JSON in transport document",
			envelope: &Envelope{
				TransportDocument:             []byte(`{invalid json}`),
				EnvelopeManifestSignedContent: "eyJhbGci...",
				EnvelopeTransferChain:         []EnvelopeTransferChainEntrySignedContent{"eyJhbGci..."},
			},
			expectError: true,
			errorMsg:    "transportDocument must be valid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.envelope.ValidateStructure()
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// TestRecreateSampleEnvelope is a sanity check to confirm we can reconstruct the test envelope using the builder
func TestRecreateSampleEnvelope(t *testing.T) {
	testEnvelopePath := "../../test/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"

	testEnvelopeData, err := os.ReadFile(testEnvelopePath)
	if err != nil {
		t.Fatalf("failed to read test envelope: %v", err)
	}

	// marshal the test envelope to json.RawMessage so we can access the fields we need
	var testEnvelope map[string]json.RawMessage
	if err := json.Unmarshal(testEnvelopeData, &testEnvelope); err != nil {
		t.Fatalf("failed to unmarshal test envelope: %v", err)
	}

	// extract the transport document from the test envelope
	transportDocument := testEnvelope["transportDocument"]

	// extract the issuance manifest from the test envelope
	envelopeManifestSignedContentRaw := testEnvelope["envelopeManifestSignedContent"]

	// this is a json string so unmarshal it (the builder expects a string not json.RawMessage)
	var envelopeManifestSignedContent string
	if err := json.Unmarshal(envelopeManifestSignedContentRaw, &envelopeManifestSignedContent); err != nil {
		t.Fatalf("failed to unmarshal envelope manifest signed content: %v", err)
	}

	// extract the transfer chain from the test envelope
	envelopeTransferChainRaw := testEnvelope["envelopeTransferChain"]
	var transferChain []EnvelopeTransferChainEntrySignedContent
	if err := json.Unmarshal(envelopeTransferChainRaw, &transferChain); err != nil {
		t.Fatalf("failed to unmarshal transfer chain: %v", err)
	}

	// use the envelope builder to recreate the envelope
	envelope, err := NewEnvelopeBuilder().
		WithTransportDocument(transportDocument).
		WithEnvelopeManifestSignedContent(EnvelopeManifestSignedContent(envelopeManifestSignedContent)).
		WithEnvelopeTransferChain(transferChain).
		Build()
	if err != nil {
		t.Fatalf("failed to build envelope: %v", err)
	}

	if err := envelope.ValidateStructure(); err != nil {
		t.Fatalf("failed to validate envelope: %v", err)
	}

	// marshal the new envelope to json
	newEnvelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("failed to marshal new envelope: %v", err)
	}

	// verify the new envelope json matches the test envelope json
	// cannonicalize the json before comparing
	canonicalTestEnvelope, err := crypto.CanonicalizeJSON(testEnvelopeData)
	if err != nil {
		t.Fatalf("failed to canonicalize test envelope: %v", err)
	}
	canonicalNewEnvelope, err := crypto.CanonicalizeJSON(newEnvelopeJSON)
	if err != nil {
		t.Fatalf("failed to canonicalize new envelope: %v", err)
	}

	if string(canonicalNewEnvelope) != string(canonicalTestEnvelope) {
		t.Fatalf("new envelope json does not match test envelope json")
	}
}

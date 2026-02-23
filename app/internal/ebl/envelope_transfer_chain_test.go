package ebl

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// test data
var (
	testTransportDoc            = []byte(`{"transportDocumentReference":"test"}`)
	testTransportDocChecksum, _ = TransportDocument(testTransportDoc).Checksum()
	testActor                   = ActorParty{
		PartyName:   "Test Carrier",
		EblPlatform: "WAVE",
		IdentifyingCodes: []IdentifyingCode{
			{CodeListProvider: "GLEIF", PartyCode: "actor"},
		},
	}
	testRecipient = RecipientParty{
		PartyName:   "Test Consignee",
		EblPlatform: "BOLE",
		IdentifyingCodes: []IdentifyingCode{
			{CodeListProvider: "GLEIF", PartyCode: "recipient"},
		},
	}
	testTransaction = Transaction{
		ActionCode:     ActionCodeIssue,
		Actor:          testActor,
		Recipient:      &testRecipient,
		ActionDateTime: "2024-01-15T10:30:00.000Z",
	}
	testIssuanceManifestJWS = IssuanceManifestSignedContent("eyJhbGci...manifest")
	testPreviousEntryJWS    = TransferChainEntrySignedContent("eyJhbGci...entry")
)

// TestEnvelopeTransferChainEntry_Sign* test the core signing functionality of transfer chain entries.
func TestEnvelopeTransferChainEntry_Sign_Ed25519_WithX5C(t *testing.T) {
	privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile("../../test/testdata/certs/ed25519-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Could not read cert chain: %v", err)
	}

	entry := createTestEntry(t)

	// Sign with x5c (keyID is auto-computed from privateKey)
	jws, err := entry.Sign(privateKey, certChain)
	if err != nil {
		t.Fatalf("Failed to sign EnvelopeTransferChainEntry: %v", err)
	}

	// Verify JWS format (header.payload.signature)
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		t.Fatalf("JWS should have 3 parts (header.payload.signature), got %d", len(parts))
	}

	// check the signature can be verified
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payload, err := crypto.VerifyJWSEd25519(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original entry (after canonicalization)
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := crypto.CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify x5c header is present
	extractedCerts, err := crypto.ParseX5CFromJWS(string(jws))
	if err != nil {
		t.Fatalf("Failed to parse x5c from JWS: %v", err)
	}

	if len(extractedCerts) != len(certChain) {
		t.Errorf("x5c chain length = %d, want %d", len(extractedCerts), len(certChain))
	}

	// Verify certificates match
	for i := range certChain {
		if !extractedCerts[i].Equal(certChain[i]) {
			t.Errorf("certificate %d mismatch", i)
		}
	}
}

// TestEnvelopeTransferChainEntry_Sign_Ed25519_NoX5C tests signing without x5c
func TestEnvelopeTransferChainEntry_Sign_Ed25519_NoX5C(t *testing.T) {
	privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../../test/testdata/keys/ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	entry := createTestEntry(t)

	// Sign without x5c (keyID is auto-computed from privateKey)
	jws, err := entry.Sign(privateKey, nil)
	if err != nil {
		t.Fatalf("Failed to sign EnvelopeTransferChainEntry: %v", err)
	}

	// Verify JWS format
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		t.Fatalf("JWS should have 3 parts, got %d", len(parts))
	}

	// Verify the signature
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payload, err := crypto.VerifyJWSEd25519(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := crypto.CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify NO x5c header
	extractedCerts, err := crypto.ParseX5CFromJWS(string(jws))
	if err != nil {
		t.Fatalf("Failed to parse JWS: %v", err)
	}

	if extractedCerts != nil {
		t.Error("x5c should not be present when signing without x5c")
	}
}

// TestEnvelopeTransferChainEntry_Sign_RSA_WithX5C tests signing with RSA and x5c
func TestEnvelopeTransferChainEntry_Sign_RSA_WithX5C(t *testing.T) {
	privateKey, err := crypto.ReadRSAPrivateKeyFromJWKFile("../../test/testdata/keys/rsa-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile("../../test/testdata/certs/rsa-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Could not read cert chain: %v", err)
	}

	entry := createTestEntry(t)

	// Sign with x5c (keyID is auto-computed from privateKey)
	jws, err := entry.Sign(privateKey, certChain)
	if err != nil {
		t.Fatalf("Failed to sign EnvelopeTransferChainEntry: %v", err)
	}

	// Verify JWS format (header.payload.signature)
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		t.Fatalf("JWS should have 3 parts (header.payload.signature), got %d", len(parts))
	}

	// Verify the signature
	publicKey := &privateKey.PublicKey
	payload, err := crypto.VerifyJWSRSA(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original entry (after canonicalization)
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := crypto.CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify x5c header is present
	extractedCerts, err := crypto.ParseX5CFromJWS(string(jws))
	if err != nil {
		t.Fatalf("Failed to parse x5c from JWS: %v", err)
	}

	if len(extractedCerts) != len(certChain) {
		t.Errorf("x5c chain length = %d, want %d", len(extractedCerts), len(certChain))
	}

	// Verify certificates match
	for i := range certChain {
		if !extractedCerts[i].Equal(certChain[i]) {
			t.Errorf("certificate %d mismatch", i)
		}
	}
}

// TestEnvelopeTransferChainEntry_Sign_RSA_NoX5C tests signing without x5c
func TestEnvelopeTransferChainEntry_Sign_RSA_NoX5C(t *testing.T) {
	privateKey, err := crypto.ReadRSAPrivateKeyFromJWKFile("../../test/testdata/keys/rsa-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	entry := createTestEntry(t)

	// Sign without x5c (keyID is auto-computed from privateKey)
	jws, err := entry.Sign(privateKey, nil)
	if err != nil {
		t.Fatalf("Failed to sign EnvelopeTransferChainEntry: %v", err)
	}

	// Verify JWS format
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		t.Fatalf("JWS should have 3 parts, got %d", len(parts))
	}

	// Verify the signature
	publicKey := &privateKey.PublicKey
	payload, err := crypto.VerifyJWSRSA(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original entry (after canonicalization)
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := crypto.CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify NO x5c header
	extractedCerts, err := crypto.ParseX5CFromJWS(string(jws))
	if err != nil {
		t.Fatalf("Failed to parse JWS: %v", err)
	}

	if extractedCerts != nil {
		t.Error("x5c should not be present when signing without x5c")
	}
}

func TestEnvelopeTransferChainEntry_Validate(t *testing.T) {
	validTransaction := Transaction{
		ActionCode:     ActionCodeIssue,
		Actor:          testActor,
		Recipient:      &testRecipient,
		ActionDateTime: "2024-01-15T10:30:00.000Z",
	}

	issuanceManifest := IssuanceManifestSignedContent("test-issuance-manifest-jws")
	prevChecksum := TransferChainEntrySignedContentChecksum("abcd1234")

	ctrURI := "https://ctr.example.com"

	tests := []struct {
		name        string
		entry       *EnvelopeTransferChainEntry
		entryNumber int
		wantErr     bool
		errMsg      string
	}{
		{
			name: "valid first entry",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				TransportDocumentChecksum:     "checksum123",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			entryNumber: 0,
			wantErr:     false,
		},
		{
			name: "valid first entry with CTR",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				TransportDocumentChecksum:     "checksum123",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
				ControlTrackingRegistry:       &ctrURI,
			},
			entryNumber: 0,
			wantErr:     false,
		},
		{
			name: "valid subsequent entry",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:               "WAVE",
				TransportDocumentChecksum: "checksum123",
				Transactions:              []Transaction{validTransaction},
				PreviousEnvelopeTransferChainEntrySignedContentChecksum: &prevChecksum,
			},
			entryNumber: 1,
			wantErr:     false,
		},
		{
			name: "invalid - both issuance manifest and previous entry",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				TransportDocumentChecksum:     "checksum123",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
				PreviousEnvelopeTransferChainEntrySignedContentChecksum: &prevChecksum,
			},
			entryNumber: 0,
			wantErr:     true,
			errMsg:      "entry cannot have both issuanceManifestSignedContent and previousEnvelopeTransferChainEntrySignedContentChecksum",
		},
		{
			name: "invalid - neither issuance manifest nor previous entry",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:               "WAVE",
				TransportDocumentChecksum: "checksum123",
				Transactions:              []Transaction{validTransaction},
			},
			entryNumber: 0,
			wantErr:     true,
			errMsg:      "issuanceManifestSignedContent is required for first entry",
		},
		{
			name: "invalid - subsequent entry with CTR",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:               "WAVE",
				TransportDocumentChecksum: "checksum123",
				Transactions:              []Transaction{validTransaction},
				PreviousEnvelopeTransferChainEntrySignedContentChecksum: &prevChecksum,
				ControlTrackingRegistry:                                 &ctrURI,
			},
			entryNumber: 1,
			wantErr:     true,
			errMsg:      "controlTrackingRegistry should only be present in first entry",
		},
		{
			name: "invalid - missing eblPlatform",
			entry: &EnvelopeTransferChainEntry{
				TransportDocumentChecksum:     "checksum123",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			entryNumber: 0,
			wantErr:     true,
			errMsg:      "eBLPlatform is required",
		},
		{
			name: "invalid - missing transportDocumentChecksum",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			entryNumber: 0,
			wantErr:     true,
			errMsg:      "transportDocumentChecksum is required",
		},
		{
			name: "invalid - missing transactions",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				TransportDocumentChecksum:     "checksum123",
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			entryNumber: 0,
			wantErr:     true,
			errMsg:      "at least one transaction is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isFirstEntry := tt.entryNumber == 0
			err := tt.entry.ValidateStructure(isFirstEntry)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestEnvelopeTransferChainEntryBuilder_FirstEntry(t *testing.T) {

	entry, err := NewEnvelopeTransferChainEntryBuilder(true).
		WithTransportDocumentChecksum(testTransportDocChecksum).
		WithTransaction(testTransaction).
		WithEBLPlatform("WAVE").
		WithIssuanceManifestSignedContent(testIssuanceManifestJWS).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Verify first entry has issuance manifest, not previous entry
	if entry.IssuanceManifestSignedContent == nil || *entry.IssuanceManifestSignedContent != testIssuanceManifestJWS {
		t.Error("IssuanceManifestSignedContent should be set for first entry")
	}
	if entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum != nil {
		t.Error("PreviousEnvelopeTransferChainEntrySignedContentChecksum should be nil for first entry")
	}

	// Verify transport document checksum was set
	if entry.TransportDocumentChecksum != TransportDocumentChecksum(testTransportDocChecksum) {
		t.Errorf("TransportDocumentChecksum = %s, want %s", entry.TransportDocumentChecksum, testTransportDocChecksum)
	}
}

func TestEnvelopeTransferChainEntryBuilder_SubsequentEntry(t *testing.T) {
	previousEntryChecksum := checksumFromToken(testPreviousEntryJWS, t)

	entry, err := NewEnvelopeTransferChainEntryBuilder(false).
		WithTransportDocumentChecksum(testTransportDocChecksum).
		WithTransaction(testTransaction).
		WithEBLPlatform("WAVE").
		WithPreviousEnvelopeTransferChainEntrySignedContentChecksum(previousEntryChecksum).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	// Verify subsequent entry has previous entry checksum, not issuance manifest
	if entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum == nil {
		t.Error("PreviousEnvelopeTransferChainEntrySignedContentChecksum should be set for subsequent entry")
	}
	if entry.IssuanceManifestSignedContent != nil {
		t.Error("IssuanceManifestSignedContent should be nil for subsequent entry")
	}

	// Verify transport document checksum was set
	if entry.TransportDocumentChecksum != TransportDocumentChecksum(testTransportDocChecksum) {
		t.Errorf("TransportDocumentChecksum = %s, want %s", entry.TransportDocumentChecksum, testTransportDocChecksum)
	}

	// Verify previous entry checksum is correct
	expectedChecksum, _ := crypto.Hash([]byte(testPreviousEntryJWS))

	if entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum == nil {
		t.Error("PreviousEnvelopeTransferChainEntrySignedContentChecksum should be set for subsequent entry")
		return
	}
	if *entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum != TransferChainEntrySignedContentChecksum(expectedChecksum) {
		t.Error("PreviousEnvelopeTransferChainEntrySignedContentChecksum mismatch")
	}
}

func TestEnvelopeTransferChainEntryBuilder_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		builder func() *EnvelopeTransferChainEntryBuilder
		errMsg  string
	}{
		{
			name: "missing transport document checksum",
			builder: func() *EnvelopeTransferChainEntryBuilder {
				return NewEnvelopeTransferChainEntryBuilder(true).
					WithEBLPlatform("WAVE").
					WithTransaction(testTransaction).
					WithIssuanceManifestSignedContent(testIssuanceManifestJWS)
			},
			errMsg: "transportDocumentChecksum is required",
		},
		{
			name: "missing eBL platform",
			builder: func() *EnvelopeTransferChainEntryBuilder {
				return NewEnvelopeTransferChainEntryBuilder(true).
					WithTransportDocumentChecksum(testTransportDocChecksum).
					WithTransaction(testTransaction).
					WithIssuanceManifestSignedContent(testIssuanceManifestJWS)
			},
			errMsg: "eBLPlatform is required",
		},
		{
			name: "missing transaction",
			builder: func() *EnvelopeTransferChainEntryBuilder {
				return NewEnvelopeTransferChainEntryBuilder(true).
					WithTransportDocumentChecksum(testTransportDocChecksum).
					WithEBLPlatform("WAVE").
					WithIssuanceManifestSignedContent(testIssuanceManifestJWS)
			},
			errMsg: "at least one transaction is required",
		},
		{
			name: "empty previous entry JWS",
			builder: func() *EnvelopeTransferChainEntryBuilder {
				return NewEnvelopeTransferChainEntryBuilder(false).
					WithTransportDocumentChecksum(testTransportDocChecksum).
					WithEBLPlatform("WAVE").
					WithTransaction(testTransaction)
			},
			errMsg: "previousEnvelopeTransferChainEntrySignedContentChecksum is required in all entries apart from the first entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.builder().Build()
			if err == nil {
				t.Error("Expected error but got none")
			} else if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error to contain %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestEnvelopeTransferChainEntryBuilder_ControlTrackingRegistry(t *testing.T) {
	ctrURI := "https://ctr.example.com/v1"

	previousEntryChecksum := checksumFromToken(testPreviousEntryJWS, t)
	t.Run("valid CTR on first entry", func(t *testing.T) {
		entry, err := NewEnvelopeTransferChainEntryBuilder(true).
			WithTransportDocumentChecksum(testTransportDocChecksum).
			WithTransaction(testTransaction).
			WithEBLPlatform("WAVE").
			WithIssuanceManifestSignedContent(testIssuanceManifestJWS).
			WithControlTrackingRegistry(ctrURI).
			Build()
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if entry.ControlTrackingRegistry == nil || *entry.ControlTrackingRegistry != ctrURI {
			t.Error("ControlTrackingRegistry should be set on first entry")
		}
	})

	t.Run("CTR on subsequent entry should fail", func(t *testing.T) {
		b := NewEnvelopeTransferChainEntryBuilder(false).
			WithTransportDocumentChecksum(testTransportDocChecksum).
			WithTransaction(testTransaction).
			WithEBLPlatform("WAVE").
			WithPreviousEnvelopeTransferChainEntrySignedContentChecksum(previousEntryChecksum).
			WithControlTrackingRegistry(ctrURI)

		t.Logf("debug builder: %+v", b)
		_, err := b.Build()
		if err == nil || !strings.Contains(err.Error(), "controlTrackingRegistry should only be present in first entry") {
			t.Errorf("Expected CTR validation error on subsequent entry, got: %v", err)
		}
	})

	t.Run("invalid CTR URL should fail", func(t *testing.T) {
		_, err := NewEnvelopeTransferChainEntryBuilder(true).
			WithTransportDocumentChecksum(testTransportDocChecksum).
			WithTransaction(testTransaction).
			WithEBLPlatform("WAVE").
			WithIssuanceManifestSignedContent(testIssuanceManifestJWS).
			WithControlTrackingRegistry("://invalid").
			Build()
		if err == nil || !strings.Contains(err.Error(), "invalid controlTrackingRegistry URL") {
			t.Errorf("Expected invalid URL error, got: %v", err)
		}
	})
}

// createTestEntry creates a minimal valid transfer chain entry for testing
func createTestEntry(t *testing.T) *EnvelopeTransferChainEntry {
	t.Helper()
	return &EnvelopeTransferChainEntry{
		EblPlatform:               "WAVE",
		TransportDocumentChecksum: "583c29ab3e47f2d80899993200d3fbadb9f8a367f3a39f715935c46d7a283006",
		Transactions: []Transaction{
			{
				ActionCode: ActionCodeIssue,
				Actor: ActorParty{
					PartyName:   "Test Carrier",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "GLEIF",
							PartyCode:        "TEST123456789",
						},
					},
				},
				Recipient: &RecipientParty{
					PartyName:   "Test Consignee",
					EblPlatform: "BOLE",
					IdentifyingCodes: []IdentifyingCode{
						{CodeListProvider: "GLEIF", PartyCode: "RECIPIENT123456"},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
		},
	}
}

func checksumFromToken(token TransferChainEntrySignedContent, t *testing.T) TransferChainEntrySignedContentChecksum {

	p, err := crypto.Hash([]byte(token))
	if err != nil {
		t.Fatalf("failed to compute checksum for previous entry: %v", err)
	}
	return TransferChainEntrySignedContentChecksum(p)
}

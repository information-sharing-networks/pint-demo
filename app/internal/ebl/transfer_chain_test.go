package ebl

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// createTestEntry creates a minimal valid transfer chain entry for testing
func createTestEntry() *EnvelopeTransferChainEntry {
	return &EnvelopeTransferChainEntry{
		EblPlatform:               "WAVE",
		TransportDocumentChecksum: "583c29ab3e47f2d80899993200d3fbadb9f8a367f3a39f715935c46d7a283006",
		Transactions: []Transaction{
			{
				ActionCode: "ISSUE",
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
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
		},
	}
}

// TestEnvelopeTransferChainEntry_Sign_Ed25519_WithX5C tests the core signing functionality
// This is the MAIN test - it verifies that transfer chain entries can be signed and verified
func TestEnvelopeTransferChainEntry_Sign_Ed25519_WithX5C(t *testing.T) {
	privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../crypto/testdata/keys/ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile("../crypto/testdata/certs/ed25519-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Could not read cert chain: %v", err)
	}

	entry := createTestEntry()

	// Sign with x5c
	jws, err := entry.Sign(privateKey, "testkid", certChain)
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
	payload, err := crypto.VerifyEd25519(string(jws), publicKey)
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
	privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../crypto/testdata/keys/ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	entry := createTestEntry()

	// Sign without x5c
	jws, err := entry.Sign(privateKey, "testkid", nil)
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
	payload, err := crypto.VerifyEd25519(string(jws), publicKey)
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
	privateKey, err := crypto.ReadRSAPrivateKeyFromJWKFile("../crypto/testdata/keys/rsa-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile("../crypto/testdata/certs/rsa-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Could not read cert chain: %v", err)
	}

	entry := createTestEntry()

	// Sign with x5c
	jws, err := entry.Sign(privateKey, "testkid", certChain)
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
	payload, err := crypto.VerifyRSA(string(jws), publicKey)
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
	privateKey, err := crypto.ReadRSAPrivateKeyFromJWKFile("../crypto/testdata/keys/rsa-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	entry := createTestEntry()

	// Sign without x5c
	jws, err := entry.Sign(privateKey, "testkid", nil)
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
	payload, err := crypto.VerifyRSA(string(jws), publicKey)
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

func TestTransaction_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tx      Transaction
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid transaction with all required fields",
			tx: Transaction{
				ActionCode: "ISSUE",
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: false,
		},
		{
			name: "valid transaction with recipient",
			tx: Transaction{
				ActionCode: "TRANSFER",
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				Recipient: &RecipientParty{
					PartyName:   "Test Recipient",
					EblPlatform: "CARX",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "GLEIF",
							PartyCode:        "LEI123456",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: false,
		},
		{
			name: "missing actionCode",
			tx: Transaction{
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "actionCode is required",
		},
		{
			name: "missing actionDateTime",
			tx: Transaction{
				ActionCode: "ISSUE",
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "actionDateTime is required",
		},
		{
			name: "invalid actor - missing partyName",
			tx: Transaction{
				ActionCode: "ISSUE",
				Actor: ActorParty{
					EblPlatform: "WAVE",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "partyName is required",
		},
		{
			name: "invalid actor - missing eblPlatform",
			tx: Transaction{
				ActionCode: "ISSUE",
				Actor: ActorParty{
					PartyName: "Test Actor",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "W3C",
							PartyCode:        "did:example:123",
						},
					},
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "eblPlatform is required",
		},
		{
			name: "invalid actor - missing identifyingCodes",
			tx: Transaction{
				ActionCode: "ISSUE",
				Actor: ActorParty{
					PartyName:   "Test Actor",
					EblPlatform: "WAVE",
				},
				ActionDateTime: "2024-04-17T07:11:19.531Z",
			},
			wantErr: true,
			errMsg:  "at least one identifyingCode is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tx.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Transaction.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				// Check if error message contains the expected substring
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Transaction.Validate() error = %v, want error containing %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestIdentifyingCode_Validate(t *testing.T) {
	tests := []struct {
		name    string
		code    IdentifyingCode
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid identifying code",
			code: IdentifyingCode{
				CodeListProvider: "W3C",
				PartyCode:        "did:example:123",
			},
			wantErr: false,
		},
		{
			name: "valid with codeListName",
			code: IdentifyingCode{
				CodeListProvider: "GLEIF",
				PartyCode:        "LEI123456",
				CodeListName:     stringPtr("LEI"),
			},
			wantErr: false,
		},
		{
			name: "missing codeListProvider",
			code: IdentifyingCode{
				PartyCode: "did:example:123",
			},
			wantErr: true,
			errMsg:  "codeListProvider is required",
		},
		{
			name: "missing partyCode",
			code: IdentifyingCode{
				CodeListProvider: "W3C",
			},
			wantErr: true,
			errMsg:  "partyCode is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.code.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("IdentifyingCode.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("IdentifyingCode.Validate() error = %v, want %v", err, tt.errMsg)
			}
		})
	}
}

func TestActorParty_Validate(t *testing.T) {
	tests := []struct {
		name    string
		party   ActorParty
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid actor party",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid with represented party",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
				RepresentedParty: &RepresentedActorParty{
					PartyName: "Represented Party",
				},
			},
			wantErr: false,
		},
		{
			name: "missing partyName",
			party: ActorParty{
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
			},
			wantErr: true,
			errMsg:  "partyName is required",
		},
		{
			name: "missing eblPlatform",
			party: ActorParty{
				PartyName: "Test Party",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						PartyCode:        "did:example:123",
					},
				},
			},
			wantErr: true,
			errMsg:  "eblPlatform is required",
		},
		{
			name: "missing identifyingCodes",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
			},
			wantErr: true,
			errMsg:  "at least one identifyingCode is required",
		},
		{
			name: "invalid identifyingCode",
			party: ActorParty{
				PartyName:   "Test Party",
				EblPlatform: "WAVE",
				IdentifyingCodes: []IdentifyingCode{
					{
						CodeListProvider: "W3C",
						// Missing PartyCode
					},
				},
			},
			wantErr: true,
			errMsg:  "partyCode is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.party.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ActorParty.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ActorParty.Validate() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

func TestEnvelopeTransferChainEntry_Validate(t *testing.T) {
	validTransaction := Transaction{
		ActionCode:     "ISSU",
		Actor:          testActor,
		ActionDateTime: "2024-01-15T10:30:00.000Z",
	}

	issuanceManifest := IssuanceManifestSignedContent("test-issuance-manifest-jws")
	prevChecksum := "abcd1234"

	ctrURI := "https://ctr.example.com"

	tests := []struct {
		name    string
		entry   *EnvelopeTransferChainEntry
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid first entry",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				TransportDocumentChecksum:     "checksum123",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			wantErr: false,
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
			wantErr: false,
		},
		{
			name: "valid subsequent entry",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:               "WAVE",
				TransportDocumentChecksum: "checksum123",
				Transactions:              []Transaction{validTransaction},
				PreviousEnvelopeTransferChainEntrySignedContentChecksum: &prevChecksum,
			},
			wantErr: false,
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
			wantErr: true,
			errMsg:  "entry cannot have both issuanceManifestSignedContent and previousEnvelopeTransferChainEntrySignedContentChecksum",
		},
		{
			name: "invalid - neither issuance manifest nor previous entry",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:               "WAVE",
				TransportDocumentChecksum: "checksum123",
				Transactions:              []Transaction{validTransaction},
			},
			wantErr: true,
			errMsg:  "entry must have either issuanceManifestSignedContent",
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
			wantErr: true,
			errMsg:  "controlTrackingRegistry should only be present in first entry",
		},
		{
			name: "invalid - missing eblPlatform",
			entry: &EnvelopeTransferChainEntry{
				TransportDocumentChecksum:     "checksum123",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			wantErr: true,
			errMsg:  "eblPlatform is required",
		},
		{
			name: "invalid - missing transportDocumentChecksum",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				Transactions:                  []Transaction{validTransaction},
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			wantErr: true,
			errMsg:  "transportDocumentChecksum is required",
		},
		{
			name: "invalid - missing transactions",
			entry: &EnvelopeTransferChainEntry{
				EblPlatform:                   "WAVE",
				TransportDocumentChecksum:     "checksum123",
				IssuanceManifestSignedContent: &issuanceManifest,
			},
			wantErr: true,
			errMsg:  "at least one transaction is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
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

var (
	testTransportDoc         = []byte(`{"transportDocumentReference":"TEST123456"}`)
	testTransportDocChecksum = computeTestChecksum(testTransportDoc) // SHA-256 of canonical JSON
	testActor                = ActorParty{
		PartyName:   "Test Carrier",
		EblPlatform: "WAVE",
		IdentifyingCodes: []IdentifyingCode{
			{CodeListProvider: "GLEIF", PartyCode: "TEST123456789"},
		},
	}
	testRecipient = RecipientParty{
		PartyName:   "Test Consignee",
		EblPlatform: "BOLE",
		IdentifyingCodes: []IdentifyingCode{
			{CodeListProvider: "GLEIF", PartyCode: "RECIPIENT123456"},
		},
	}
	testTransaction = Transaction{
		ActionCode:     "ISSU",
		Actor:          testActor,
		Recipient:      &testRecipient,
		ActionDateTime: "2024-01-15T10:30:00.000Z",
	}
	testIssuanceManifestJWS = IssuanceManifestSignedContent("eyJhbGci...MOCK_ISSUANCE_MANIFEST")
	testPreviousEntryJWS    = EnvelopeTransferChainEntrySignedContent("eyJhbGci...MOCK_PREVIOUS_ENTRY")
)

// computeTestChecksum computes the SHA-256 checksum of canonical JSON for testing
func computeTestChecksum(jsonData []byte) string {
	canonical, err := crypto.CanonicalizeJSON(jsonData)
	if err != nil {
		panic("failed to canonicalize test data: " + err.Error())
	}
	checksum, err := crypto.Hash(canonical)
	if err != nil {
		panic("failed to crypto.Hash test data: " + err.Error())
	}
	return checksum
}

func TestEnvelopeTransferChainEntryBuilder_FirstEntry(t *testing.T) {
	entry, err := NewFirstEnvelopeTransferChainEntryBuilder(testIssuanceManifestJWS).
		WithTransportDocumentChecksum(testTransportDocChecksum).
		WithTransaction(testTransaction).
		WithEBLPlatform("WAVE").
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
	if entry.TransportDocumentChecksum != testTransportDocChecksum {
		t.Errorf("TransportDocumentChecksum = %s, want %s", entry.TransportDocumentChecksum, testTransportDocChecksum)
	}
}

func TestEnvelopeTransferChainEntryBuilder_SubsequentEntry(t *testing.T) {
	entry, err := NewSubsequentEnvelopeTransferChainEntryBuilder(testPreviousEntryJWS).
		WithTransportDocumentChecksum(testTransportDocChecksum).
		WithTransaction(testTransaction).
		WithEBLPlatform("WAVE").
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
	if entry.TransportDocumentChecksum != testTransportDocChecksum {
		t.Errorf("TransportDocumentChecksum = %s, want %s", entry.TransportDocumentChecksum, testTransportDocChecksum)
	}

	// Verify previous entry checksum is correct
	expectedChecksum, _ := crypto.Hash([]byte(testPreviousEntryJWS))
	if *entry.PreviousEnvelopeTransferChainEntrySignedContentChecksum != expectedChecksum {
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
				return NewFirstEnvelopeTransferChainEntryBuilder(testIssuanceManifestJWS).
					WithEBLPlatform("WAVE").
					WithTransaction(testTransaction)
			},
			errMsg: "transport document checksum is required",
		},
		{
			name: "missing eBL platform",
			builder: func() *EnvelopeTransferChainEntryBuilder {
				return NewFirstEnvelopeTransferChainEntryBuilder(testIssuanceManifestJWS).
					WithTransportDocumentChecksum(testTransportDocChecksum).
					WithTransaction(testTransaction)
			},
			errMsg: "eBL platform is required",
		},
		{
			name: "missing transaction",
			builder: func() *EnvelopeTransferChainEntryBuilder {
				return NewFirstEnvelopeTransferChainEntryBuilder(testIssuanceManifestJWS).
					WithTransportDocumentChecksum(testTransportDocChecksum).
					WithEBLPlatform("WAVE")
			},
			errMsg: "at least one transaction is required",
		},
		{
			name: "empty previous entry JWS",
			builder: func() *EnvelopeTransferChainEntryBuilder {
				return NewSubsequentEnvelopeTransferChainEntryBuilder("").
					WithTransportDocumentChecksum(testTransportDocChecksum).
					WithEBLPlatform("WAVE").
					WithTransaction(testTransaction)
			},
			errMsg: "entry must have either issuanceManifestSignedContent",
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

	t.Run("valid CTR on first entry", func(t *testing.T) {
		entry, err := NewFirstEnvelopeTransferChainEntryBuilder(testIssuanceManifestJWS).
			WithTransportDocumentChecksum(testTransportDocChecksum).
			WithTransaction(testTransaction).
			WithEBLPlatform("WAVE").
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
		_, err := NewSubsequentEnvelopeTransferChainEntryBuilder(testPreviousEntryJWS).
			WithTransportDocumentChecksum(testTransportDocChecksum).
			WithTransaction(testTransaction).
			WithEBLPlatform("WAVE").
			WithControlTrackingRegistry(ctrURI).
			Build()

		if err == nil || !strings.Contains(err.Error(), "controlTrackingRegistry should only be present in first entry") {
			t.Errorf("Expected CTR validation error on subsequent entry, got: %v", err)
		}
	})

	t.Run("invalid CTR URL should fail", func(t *testing.T) {
		_, err := NewFirstEnvelopeTransferChainEntryBuilder(testIssuanceManifestJWS).
			WithTransportDocumentChecksum(testTransportDocChecksum).
			WithTransaction(testTransaction).
			WithEBLPlatform("WAVE").
			WithControlTrackingRegistry("://invalid").
			Build()

		if err == nil || !strings.Contains(err.Error(), "invalid controlTrackingRegistry URL") {
			t.Errorf("Expected invalid URL error, got: %v", err)
		}
	})
}

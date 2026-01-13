package crypto

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
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

// TestEnvelopeTransferChainEntry_SignWithEd25519AndX5C tests the core signing functionality
// This is the MAIN test - it verifies that transfer chain entries can be signed and verified
func TestEnvelopeTransferChainEntry_SignWithEd25519AndX5C(t *testing.T) {
	privateKey, err := ReadEd25519PrivateKeyFromJWKFile("testdata/transport-documents/keys", "ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	certChain, err := ReadCertChainFromPEMFile("testdata/transport-documents/certs", "ed25519-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Could not read cert chain: %v", err)
	}

	entry := createTestEntry()

	// Sign with x5c
	jws, err := entry.SignWithEd25519AndX5C(privateKey, "testkid", certChain)
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
	payload, err := VerifyEd25519(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original entry (after canonicalization)
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify x5c header is present
	extractedCerts, err := ParseX5CFromJWS(string(jws))
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

// TestEnvelopeTransferChainEntry_SignWithEd25519 tests signing without x5c
func TestEnvelopeTransferChainEntry_SignWithEd25519(t *testing.T) {
	privateKey, err := ReadEd25519PrivateKeyFromJWKFile("testdata/transport-documents/keys", "ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	entry := createTestEntry()

	// Sign without x5c
	jws, err := entry.SignWithEd25519(privateKey, "testkid")
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
	payload, err := VerifyEd25519(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify NO x5c header
	extractedCerts, err := ParseX5CFromJWS(string(jws))
	if err != nil {
		t.Fatalf("Failed to parse JWS: %v", err)
	}

	if extractedCerts != nil {
		t.Error("x5c should not be present when signing without x5c")
	}
}

// TestEnvelopeTransferChainEntry_SignWithRSAAndX5C tests signing with RSA and x5c
func TestEnvelopeTransferChainEntry_SignWithRSAAndX5C(t *testing.T) {
	privateKey, err := ReadRSAPrivateKeyFromJWKFile("testdata/transport-documents/keys", "rsa-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	certChain, err := ReadCertChainFromPEMFile("testdata/transport-documents/certs", "rsa-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Could not read cert chain: %v", err)
	}

	entry := createTestEntry()

	// Sign with x5c
	jws, err := entry.SignWithRSAAndX5C(privateKey, "testkid", certChain)
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
	payload, err := VerifyRSA(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original entry (after canonicalization)
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify x5c header is present
	extractedCerts, err := ParseX5CFromJWS(string(jws))
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

// TestEnvelopeTransferChainEntry_SignWithRSA tests signing without x5c
func TestEnvelopeTransferChainEntry_SignWithRSA(t *testing.T) {
	privateKey, err := ReadRSAPrivateKeyFromJWKFile("testdata/transport-documents/keys", "rsa-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Could not read private key: %v", err)
	}

	entry := createTestEntry()

	// Sign without x5c
	jws, err := entry.SignWithRSA(privateKey, "testkid")
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
	payload, err := VerifyRSA(string(jws), publicKey)
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	// Verify payload matches original entry (after canonicalization)
	originalJSON, _ := json.Marshal(entry)
	canonicalOriginal, _ := CanonicalizeJSON(originalJSON)

	if string(payload) != string(canonicalOriginal) {
		t.Error("Verified payload does not match original canonical entry")
	}

	// Verify NO x5c header
	extractedCerts, err := ParseX5CFromJWS(string(jws))
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
				if !contains(err.Error(), tt.errMsg) {
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
			if err != nil && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("ActorParty.Validate() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

package ebl

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl/testutil"
)

// TestVerifyValidEnvelopeTransfer tests valid envelopes using different signature algorithms
// the files used were created independently of the pint-demo code, and is used as a
// sanity check that the verification code can handle valid envelopes.
func TestVerifyEnvelopeTransfer_ValidEnvelopes(t *testing.T) {

	testData := []struct {
		name                  string
		eblEnvelopePath       string
		publicKeyJWKPath      string
		carrierPublicKeyPath  string
		rootCACertPath        string
		expectedSenderDomain  string
		expectedCarrierDomain string
		recipientPlatformCode string
		senderPlatformCode    string // Platform code for the sender's key in KeyProvider
		carrierPlatformCode   string // Platform code for the carrier's key in KeyProvider
	}{
		{
			name:                  "verifies Ed25519 signed envelope",
			eblEnvelopePath:       "../../test/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json",
			publicKeyJWKPath:      "../../test/testdata/keys/ed25519-eblplatform.example.com.public.jwk",
			carrierPublicKeyPath:  "../../test/testdata/keys/ed25519-carrier.example.com.public.jwk",
			rootCACertPath:        "../../test/testdata/certs/root-ca.crt", // all the test certs are signed by the same root CA
			expectedSenderDomain:  "ed25519-eblplatform.example.com",
			expectedCarrierDomain: "ed25519-carrier.example.com",
			recipientPlatformCode: "EBL2",
			senderPlatformCode:    "EBL1",
			carrierPlatformCode:   "CAR1",
		},
		{
			name:                  "verifies RSA signed envelope",
			eblEnvelopePath:       "../../test/testdata/pint-transfers/HHL71800000-ebl-envelope-rsa.json",
			publicKeyJWKPath:      "../../test/testdata/keys/rsa-eblplatform.example.com.public.jwk",
			carrierPublicKeyPath:  "../../test/testdata/keys/rsa-carrier.example.com.public.jwk",
			rootCACertPath:        "../../test/testdata/certs/root-ca.crt",
			expectedSenderDomain:  "rsa-eblplatform.example.com",
			expectedCarrierDomain: "rsa-carrier.example.com",
			recipientPlatformCode: "EBL1",
			senderPlatformCode:    "EBL2",
			carrierPlatformCode:   "CAR2",
		},
	}
	for _, test := range testData {
		t.Run(test.name, func(t *testing.T) {

			// Load the test envelope
			envelopeBytes, err := os.ReadFile(test.eblEnvelopePath)
			if err != nil {
				t.Fatalf("Failed to read test envelope: %v", err)
			}

			var envelope EblEnvelope
			if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
				t.Fatalf("Failed to parse envelope: %v", err)
			}

			// get the public key from the JWK
			publicKey, err := crypto.ReadPublicKeyFromJWKFile(test.publicKeyJWKPath)
			if err != nil {
				t.Fatalf("Failed to read public key from JWK file: %v", err)
			}

			// get the carrier public key from the JWK
			carrierPublicKey, err := crypto.ReadPublicKeyFromJWKFile(test.carrierPublicKeyPath)
			if err != nil {
				t.Fatalf("Failed to read carrier public key from JWK file: %v", err)
			}

			// get public key from root CA cert
			rootCAs, err := testutil.LoadTestRootCA(test.rootCACertPath)
			if err != nil {
				t.Fatalf("Failed to load root CA: %v", err)
			}

			// Extract KIDs from the JWS headers to populate the mock KeyProvider
			senderHeader, err := crypto.ParseJWSHeader(string(envelope.EnvelopeManifestSignedContent))
			if err != nil {
				t.Fatalf("Failed to parse sender JWS header: %v", err)
			}

			// Extract carrier KID from first transfer chain entry
			firstEntryPayload, err := testutil.DecodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
			if err != nil {
				t.Fatalf("Failed to decode first transfer chain entry: %v", err)
			}

			// Get issuanceManifestSignedContent from the first entry
			issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string)
			if !ok {
				t.Fatalf("issuanceManifestSignedContent not found in first transfer chain entry")
			}

			carrierHeader, err := crypto.ParseJWSHeader(issuanceManifestRaw)
			if err != nil {
				t.Fatalf("Failed to parse carrier JWS header: %v", err)
			}

			// Create mock KeyProvider with both keys
			// Map KIDs to platform codes based on test data
			keyProvider := testutil.NewMockKeyProvider()
			keyProvider.AddKeyWithPlatform(senderHeader.KeyID, publicKey, test.senderPlatformCode)
			keyProvider.AddKeyWithPlatform(carrierHeader.KeyID, carrierPublicKey, test.carrierPlatformCode)

			// Create verification input
			input := EnvelopeVerificationInput{
				Envelope:              &envelope,
				RootCAs:               rootCAs,
				KeyProvider:           keyProvider,
				RecipientPlatformCode: test.recipientPlatformCode,
			}

			// Verify the envelope
			result, err := VerifyEnvelope(input)
			if err != nil {
				t.Fatalf("Envelope verification failed: %v", err)
			}

			if result.Manifest == nil {
				t.Errorf("Expected manifest to be extracted, but got nil")
			}

			if len(result.TransferChain) == 0 {
				t.Errorf("Expected transfer chain to be extracted, but got empty")
			}

			if result.FirstTransferChainEntry == nil {
				t.Errorf("Expected first transfer chain entry to be extracted, but got nil")
			}

			if result.LastTransferChainEntry == nil {
				t.Errorf("Expected last transfer chain entry to be extracted, but got nil")
			}

			// Verify convenience pointers match the slice
			if result.FirstTransferChainEntry != result.TransferChain[0] {
				t.Errorf("FirstTransferChainEntry should point to first element of TransferChain")
			}

			if result.LastTransferChainEntry != result.TransferChain[len(result.TransferChain)-1] {
				t.Errorf("LastTransferChainEntry should point to last element of TransferChain")
			}

			// Validate trust level
			if result.TrustLevel == crypto.TrustLevelNoX5C {
				t.Errorf("Expected x5c certificate chain, but got TrustLevelNoX5C")
			}

			// Validate verified domain
			if result.VerifiedDomain == "" {
				t.Errorf("Expected verified domain to be populated")
			}
			if result.VerifiedDomain != test.expectedSenderDomain {
				t.Errorf("Expected verified domain to match input domain: got %q, want %q",
					result.VerifiedDomain, test.expectedSenderDomain)
			}

			// Validate organisation name is populated for x5c certificates
			// (Our test certs have Organization field, so this should be populated)
			if result.VerifiedOrganisation == "" {
				t.Errorf("Expected certificate organisation to be populated for x5c certificate")
			}

			if result.TransportDocumentChecksum == "" {
				t.Errorf("Expected transport document checksum to be computed, but got empty string")
			}

			// Validate transportDocumentReference is extracted
			if result.TransportDocumentReference == "" {
				t.Errorf("Expected transportDocumentReference to be extracted, but got empty string")
			}
			expectedTransportDocRef := "HHL71800000"
			if result.TransportDocumentReference != expectedTransportDocRef {
				t.Errorf("Expected transportDocumentReference to be %s, but got %s", expectedTransportDocRef, result.TransportDocumentReference)
			}

			t.Logf("Envelope verification successful for %s (with carrier signature verification, %d transfer chain entries)",
				filepath.Base(test.eblEnvelopePath), len(result.TransferChain))
		})
	}
}

var (
	validEnvelopePath         = "../../test/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"
	validPublicKeyPath        = "../../test/testdata/keys/ed25519-eblplatform.example.com.public.jwk"
	validCarrierPublicKeyPath = "../../test/testdata/keys/ed25519-carrier.example.com.public.jwk"
	validPrivateKeyPath       = "../../test/testdata/keys/ed25519-eblplatform.example.com.private.jwk"
	validFullChainPath        = "../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt"
	validRootCAPath           = "../../test/testdata/certs/root-ca.crt"
	validDomain               = "ed25519-eblplatform.example.com"
	wrongPublicKeyPath        = "../../test/testdata/keys/rsa-eblplatform.example.com.public.jwk"
)

func TestVerifyEnvelopeTransfer_ErrorConditions(t *testing.T) {

	tests := []struct {
		name            string
		tamperEnvelope  func(*EblEnvelope) error
		publicKeyPath   string
		domain          string
		useWrongCAPath  bool
		wantErrCode     string
		wantErrContains string
	}{
		// signature errors
		{
			name:            "returns BSIG when incorrect public key",
			publicKeyPath:   wrongPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BSIG",
			wantErrContains: "JWS verification failed", // Signature fails before x5c check
		},
		{
			name: "returns BSIG when envelope manifest signature invalid",
			tamperEnvelope: func(env *EblEnvelope) error {
				// Modify the manifest JWS by replacing the payload
				parts := strings.Split(string(env.EnvelopeManifestSignedContent), ".")
				if len(parts) != 3 {
					return fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
				}
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"tampered": "data"}`))
				env.EnvelopeManifestSignedContent = EnvelopeManifestSignedContent(strings.Join(parts, "."))
				return nil
			},
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BSIG",
			wantErrContains: "JWS verification failed",
		},
		{
			name:            "returns BSIG when wrong root CA",
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  true,
			wantErrCode:     "BSIG",
			wantErrContains: "certificate chain validation failed",
		},
		// Envelope integrity errors
		{
			name: "returns BENV when transfer chain entry signature tampered",
			tamperEnvelope: func(env *EblEnvelope) error {
				if len(env.EnvelopeTransferChain) == 0 {
					return fmt.Errorf("empty transfer chain")
				}
				// Tamper with the last entry's signature
				lastIdx := len(env.EnvelopeTransferChain) - 1
				jws := string(env.EnvelopeTransferChain[lastIdx])
				parts := strings.Split(string(jws), ".")
				if len(parts) != 3 {
					return fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
				}
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"tampered": "data"}`))
				env.EnvelopeTransferChain[lastIdx] = EnvelopeTransferChainEntrySignedContent(strings.Join(parts, "."))
				return nil
			},
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BENV",
			wantErrContains: "last transfer chain entry checksum does not match the manifest",
		},
		{
			name: "returns BENV when transport document tampered",
			tamperEnvelope: func(env *EblEnvelope) error {
				env.TransportDocument = json.RawMessage(`{"tampered": "data"}`)
				return nil
			},
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BENV",
			wantErrContains: "transport document checksum mismatch",
		},
		{
			name: "returns BENV when missing transportDocumentReference",
			tamperEnvelope: func(env *EblEnvelope) error {
				// Create a transport document WITHOUT transportDocumentReference
				// This tests that a malicious actor can't create a properly signed envelope
				// with a valid checksum but missing the required field
				var transportDoc map[string]any
				if err := json.Unmarshal(env.TransportDocument, &transportDoc); err != nil {
					return err
				}
				delete(transportDoc, "transportDocumentReference")
				modifiedDoc, err := json.Marshal(transportDoc)
				if err != nil {
					return err
				}

				// Compute the correct checksum for the modified document
				canonicalJSON, err := crypto.CanonicalizeJSON(modifiedDoc)
				if err != nil {
					return err
				}
				newChecksum, err := crypto.Hash(canonicalJSON)
				if err != nil {
					return err
				}

				// Update the transport document
				env.TransportDocument = modifiedDoc

				// Re-build and re-sign the manifest with the new checksum
				// This creates a properly signed envelope with valid checksums but missing required field
				newManifest, err := NewEnvelopeManifestBuilder().
					WithTransportDocument(modifiedDoc).
					WithLastTransferChainEntry(env.EnvelopeTransferChain[len(env.EnvelopeTransferChain)-1]).
					Build()
				if err != nil {
					return err
				}

				// Verify the checksum matches what we expect
				if newManifest.TransportDocumentChecksum != newChecksum {
					return fmt.Errorf("checksum mismatch in test setup: expected %s, got %s", newChecksum, newManifest.TransportDocumentChecksum)
				}

				// Sign the new manifest
				privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile(validPrivateKeyPath)
				if err != nil {
					return err
				}

				certChain, err := crypto.ReadCertChainFromPEMFile(validFullChainPath)
				if err != nil {
					return err
				}

				newManifestJWS, err := newManifest.Sign(privateKey, certChain)
				if err != nil {
					return err
				}

				env.EnvelopeManifestSignedContent = newManifestJWS
				return nil
			},
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BENV",
			wantErrContains: "transportDocumentReference is required",
		},
		{
			name: "returns BENV when transfer chain empty",
			tamperEnvelope: func(env *EblEnvelope) error {
				env.EnvelopeTransferChain = []EnvelopeTransferChainEntrySignedContent{}
				return nil
			},
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BENV",
			wantErrContains: "envelope transfer chain is empty",
		},
		{
			name: "returns DISE when invalid state transition SURRENDER_FOR_DELIVERY followed by TRANSFER",
			tamperEnvelope: func(env *EblEnvelope) error {
				// Decode the last transfer chain entry (which has a TRANSFER transaction)
				lastIdx := len(env.EnvelopeTransferChain) - 1
				lastEntryPayload, err := testutil.DecodeJWSPayload(string(env.EnvelopeTransferChain[lastIdx]))
				if err != nil {
					return fmt.Errorf("failed to decode last entry: %w", err)
				}

				// Get the existing transactions
				transactions, ok := lastEntryPayload["transactions"].([]any)
				if !ok {
					return fmt.Errorf("transactions field is not an array")
				}

				if len(transactions) == 0 {
					return fmt.Errorf("no transactions in last entry")
				}

				// Keep the existing TRANSFER transaction, but add SURRENDER_FOR_DELIVERY and then another TRANSFER
				firstTx := transactions[0].(map[string]any)

				// Create a SURRENDER_FOR_DELIVERY transaction
				surrenderTx := make(map[string]any)
				surrenderTx["actionCode"] = "SURRENDER_FOR_DELIVERY"
				surrenderTx["actionDateTime"] = "2024-01-17T14:22:00.000Z"
				surrenderTx["actor"] = firstTx["actor"]

				// Create a TRANSFER transaction
				transferTx := make(map[string]any)
				transferTx["actionCode"] = "TRANSFER"
				transferTx["actionDateTime"] = "2024-01-17T15:22:00.000Z"
				transferTx["actor"] = firstTx["actor"]
				transferTx["recipient"] = firstTx["recipient"]

				// Add both new transactions
				transactions = append(transactions, surrenderTx, transferTx)
				lastEntryPayload["transactions"] = transactions

				// Re-sign the modified entry
				modifiedPayloadJSON, err := json.Marshal(lastEntryPayload)
				if err != nil {
					return fmt.Errorf("failed to marshal modified payload: %w", err)
				}

				privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile(validPrivateKeyPath)
				if err != nil {
					return fmt.Errorf("failed to read private key: %w", err)
				}

				certChain, err := crypto.ReadCertChainFromPEMFile(validFullChainPath)
				if err != nil {
					return fmt.Errorf("failed to read cert chain: %w", err)
				}

				publicKey := privateKey.Public().(ed25519.PublicKey)
				keyID, err := crypto.GenerateKeyIDFromEd25519Key(publicKey)
				if err != nil {
					return fmt.Errorf("failed to compute key ID: %w", err)
				}

				modifiedEntryJWS, err := crypto.SignJSONWithEd25519AndX5C(modifiedPayloadJSON, privateKey, keyID, certChain)
				if err != nil {
					return fmt.Errorf("failed to sign modified entry: %w", err)
				}

				// Replace the last entry
				env.EnvelopeTransferChain[lastIdx] = EnvelopeTransferChainEntrySignedContent(modifiedEntryJWS)

				// Update the manifest to point to the new last entry
				transportDocJSON, err := json.Marshal(env.TransportDocument)
				if err != nil {
					return fmt.Errorf("failed to marshal transport document: %w", err)
				}

				envelopeManifest, err := NewEnvelopeManifestBuilder().
					WithTransportDocument(transportDocJSON).
					WithLastTransferChainEntry(env.EnvelopeTransferChain[lastIdx]).
					Build()
				if err != nil {
					return fmt.Errorf("failed to create envelope manifest: %w", err)
				}

				envelopeManifestJWS, err := envelopeManifest.Sign(privateKey, certChain)
				if err != nil {
					return fmt.Errorf("failed to sign envelope manifest: %w", err)
				}

				env.EnvelopeManifestSignedContent = envelopeManifestJWS
				return nil
			},
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "DISE",
			wantErrContains: "invalid state transition from SURRENDER_FOR_DELIVERY to TRANSFER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load valid envelope
			envelopeBytes, err := os.ReadFile(validEnvelopePath)
			if err != nil {
				t.Fatalf("Failed to read test envelope: %v", err)
			}

			var envelope EblEnvelope
			if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
				t.Fatalf("Failed to parse envelope: %v", err)
			}

			// Apply tampering if specified
			if tt.tamperEnvelope != nil {
				if err := tt.tamperEnvelope(&envelope); err != nil {
					if strings.Contains(err.Error(), "skip") {
						t.Skip(err.Error())
					}
					t.Fatalf("Failed to tamper envelope: %v", err)
				}
			}

			// Get public key
			publicKey, err := crypto.ReadPublicKeyFromJWKFile(tt.publicKeyPath)
			if err != nil {
				t.Fatalf("Failed to read public key: %v", err)
			}

			// Get carrier public key
			carrierPublicKey, err := crypto.ReadPublicKeyFromJWKFile(validCarrierPublicKeyPath)
			if err != nil {
				t.Fatalf("Failed to read carrier public key: %v", err)
			}

			rootCAs, err := testutil.LoadTestRootCA(validRootCAPath)
			if err != nil {
				t.Fatalf("Failed to load root CA: %v", err)
			}
			if tt.useWrongCAPath {
				rootCAs = nil // this will make the verification function use system roots
			}

			// Extract KIDs and create mock KeyProvider
			keyProvider := testutil.NewMockKeyProvider()

			// Only extract KIDs if the envelope has the required fields
			// (some tests intentionally create invalid envelopes)
			if len(envelope.EnvelopeManifestSignedContent) > 0 {
				senderHeader, err := crypto.ParseJWSHeader(string(envelope.EnvelopeManifestSignedContent))
				if err == nil {
					// Use EBL1 as default platform for error condition tests
					keyProvider.AddKeyWithPlatform(senderHeader.KeyID, publicKey, "EBL1")
				}
			}

			if len(envelope.EnvelopeTransferChain) > 0 {
				firstEntryPayload, err := testutil.DecodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
				if err == nil {
					if issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string); ok {
						carrierHeader, err := crypto.ParseJWSHeader(issuanceManifestRaw)
						if err == nil {
							// Use CAR1 as default carrier platform for error condition tests
							keyProvider.AddKeyWithPlatform(carrierHeader.KeyID, carrierPublicKey, "CAR1")
						}
					}
				}
			}

			// Create verification input
			input := EnvelopeVerificationInput{
				Envelope:    &envelope,
				RootCAs:     rootCAs,
				KeyProvider: keyProvider,
			}

			// Verify the envelope - should fail
			_, err = VerifyEnvelope(input)

			// Check we got an error
			if err == nil {
				t.Fatal("Expected verification to fail, but it succeeded")
			}

			// Check for expected error code using errors.As
			var eblErr Error
			if errors.As(err, &eblErr) {
				if string(eblErr.Code()) != tt.wantErrCode {
					t.Errorf("Expected error code %q, got %q", tt.wantErrCode, eblErr.Code())
				}
			} else {
				t.Errorf("Expected EblError with code %q, but got: %v", tt.wantErrCode, err)
			}

			// Check for expected error message substring (for additional context)
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("Expected error to contain %q, but got: %v", tt.wantErrContains, err)
			}
		})
	}
}

// TestVerifyEnvelopeTransfer_BrokenChainLink tests that verification detects when
// a transfer chain entry has an invalid previousEnvelopeTransferChainEntrySignedContentChecksum.
//
// TODO: this test (and the one following) would be better done with an independently generated test envelope since the current test
// relies on the app's manifest builder to create an envelope with bad transfer chains
func TestVerifyEnvelopeTransfer_BrokenChainLink(t *testing.T) {
	// Load test keys and certs
	privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile(validPrivateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile(validFullChainPath)
	if err != nil {
		t.Fatalf("Failed to read cert chain: %v", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := crypto.GenerateKeyIDFromEd25519Key(publicKey)
	if err != nil {
		t.Fatalf("Failed to compute key ID: %v", err)
	}

	// Load the valid envelope
	envelope, err := loadEnvelopeFromFile(t, validEnvelopePath)
	if err != nil {
		t.Fatalf("failed to load valid envelope: %v", err)
	}

	if len(envelope.EnvelopeTransferChain) < 2 {
		t.Fatalf("test envelope must have at least 2 transfer chain entries")
	}

	// Decode the second entry's payload
	secondEntryPayload, err := testutil.DecodeJWSPayload(string(envelope.EnvelopeTransferChain[1]))
	if err != nil {
		t.Fatalf("failed to decode second entry payload: %v", err)
	}

	// Set a fake previous entry checksum
	secondEntryPayload["previousEnvelopeTransferChainEntrySignedContentChecksum"] = "0000000000000000000000000000000000000000000000000000000000000000"

	// Re-sign the modified entry
	modifiedPayloadJSON, err := json.Marshal(secondEntryPayload)
	if err != nil {
		t.Fatalf("failed to marshal modified payload: %v", err)
	}

	modifiedEntryJWS, err := crypto.SignJSONWithEd25519AndX5C(modifiedPayloadJSON, privateKey, keyID, certChain)
	if err != nil {
		t.Fatalf("failed to sign modified entry: %v", err)
	}

	// Replace the second entry with the broken one
	envelope.EnvelopeTransferChain[1] = EnvelopeTransferChainEntrySignedContent(modifiedEntryJWS)

	// Update the manifest to point to the new (broken) second entry
	// This ensures the manifest checksum matches, but the chain link is broken
	transportDocJSON, err := json.Marshal(envelope.TransportDocument)
	if err != nil {
		t.Fatalf("failed to marshal transport document: %v", err)
	}

	envelopeManifest, err := NewEnvelopeManifestBuilder().
		WithTransportDocument(transportDocJSON).
		WithLastTransferChainEntry(envelope.EnvelopeTransferChain[1]).
		Build()
	if err != nil {
		t.Fatalf("failed to create envelope manifest: %v", err)
	}

	envelopeManifestJWS, err := envelopeManifest.Sign(privateKey, certChain)
	if err != nil {
		t.Fatalf("failed to sign envelope manifest: %v", err)
	}

	envelope.EnvelopeManifestSignedContent = envelopeManifestJWS

	// Load root CA
	rootCAs, err := testutil.LoadTestRootCA(validRootCAPath)
	if err != nil {
		t.Fatalf("Failed to load root CA: %v", err)
	}

	// Get carrier public key
	carrierPublicKey, err := crypto.ReadPublicKeyFromJWKFile(validCarrierPublicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read carrier public key: %v", err)
	}

	// Extract KIDs and create mock KeyProvider
	senderHeader, err := crypto.ParseJWSHeader(string(envelope.EnvelopeManifestSignedContent))
	if err != nil {
		t.Fatalf("Failed to parse sender JWS header: %v", err)
	}

	firstEntryPayload, err := testutil.DecodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
	if err != nil {
		t.Fatalf("Failed to decode first transfer chain entry: %v", err)
	}

	issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string)
	if !ok {
		t.Fatalf("issuanceManifestSignedContent not found in first transfer chain entry")
	}

	carrierHeader, err := crypto.ParseJWSHeader(issuanceManifestRaw)
	if err != nil {
		t.Fatalf("Failed to parse carrier JWS header: %v", err)
	}

	keyProvider := testutil.NewMockKeyProvider()
	keyProvider.AddKeyWithPlatform(senderHeader.KeyID, privateKey.Public(), "EBL1")
	keyProvider.AddKeyWithPlatform(carrierHeader.KeyID, carrierPublicKey, "CAR1")

	// Verify the envelope - should fail
	input := EnvelopeVerificationInput{
		Envelope:    envelope,
		RootCAs:     rootCAs,
		KeyProvider: keyProvider,
	}

	_, err = VerifyEnvelope(input)
	if err == nil {
		t.Fatal("Expected verification to fail for broken chain link, but it succeeded")
	}

	// Check for expected error - should detect the broken chain link
	if !strings.Contains(err.Error(), "chain link broken") {
		t.Errorf("Expected error about broken chain link, but got: %v", err)
	}
}

// TestVerifyEnvelopeTransfer_TamperedTransferChain tests that verification
// detects when the transfer chain has been tampered with.
func TestVerifyEnvelopeTransfer_TamperedTransferChain(t *testing.T) {

	// Load test keys and certs
	privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile(validPrivateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile(validFullChainPath)
	if err != nil {
		t.Fatalf("Failed to read cert chain: %v", err)
	}

	envelope, err := loadEnvelopeFromFile(t, validEnvelopePath)
	if err != nil {
		t.Fatalf("failed to load valid envelope: %v", err)
	}

	if len(envelope.EnvelopeTransferChain) < 2 {
		t.Fatalf("test envelope must have at least 2 transfer chain entries")
	}

	// get the transport document
	transportDocJSON, err := json.Marshal(envelope.TransportDocument)
	if err != nil {
		t.Fatalf("failed to marshal transport document: %v", err)
	}

	// Create a new manifest with the wrong last transfer chain entry
	issuanceTransferChainEntry := envelope.EnvelopeTransferChain[0] // this is the issuance entry created by CAR1

	envelopeManifest, err := NewEnvelopeManifestBuilder().
		WithTransportDocument(transportDocJSON).
		WithLastTransferChainEntry(issuanceTransferChainEntry).
		Build()
	if err != nil {
		t.Fatalf("failed to create envelope manifest: %v", err)
	}

	envelopeManifestJWS, err := envelopeManifest.Sign(privateKey, certChain)
	if err != nil {
		t.Fatalf("failed to sign envelope manifest: %v", err)
	}

	// Replace the manifest with the wrong one
	envelope.EnvelopeManifestSignedContent = envelopeManifestJWS

	// Load root CA
	rootCAs, err := testutil.LoadTestRootCA(validRootCAPath)
	if err != nil {
		t.Fatalf("Failed to load root CA: %v", err)
	}

	// Get carrier public key
	carrierPublicKey, err := crypto.ReadPublicKeyFromJWKFile(validCarrierPublicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read carrier public key: %v", err)
	}

	// Extract KIDs and create mock KeyProvider
	senderHeader, err := crypto.ParseJWSHeader(string(envelope.EnvelopeManifestSignedContent))
	if err != nil {
		t.Fatalf("Failed to parse sender JWS header: %v", err)
	}

	firstEntryPayload, err := testutil.DecodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
	if err != nil {
		t.Fatalf("Failed to decode first transfer chain entry: %v", err)
	}

	issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string)
	if !ok {
		t.Fatalf("issuanceManifestSignedContent not found in first transfer chain entry")
	}

	carrierHeader, err := crypto.ParseJWSHeader(issuanceManifestRaw)
	if err != nil {
		t.Fatalf("Failed to parse carrier JWS header: %v", err)
	}

	keyProvider := testutil.NewMockKeyProvider()
	keyProvider.AddKeyWithPlatform(senderHeader.KeyID, privateKey.Public(), "EBL1")
	keyProvider.AddKeyWithPlatform(carrierHeader.KeyID, carrierPublicKey, "CAR1")

	// Verify the envelope - should fail
	input := EnvelopeVerificationInput{
		Envelope:    envelope,
		RootCAs:     rootCAs,
		KeyProvider: keyProvider,
	}

	_, err = VerifyEnvelope(input)
	if err == nil {
		t.Fatal("Expected verification to fail for wrong manifest checksum, but it succeeded")
	}

	// Check for expected error
	if !strings.Contains(err.Error(), "the last transfer chain entry checksum does not match the manifest") {
		t.Errorf("Expected error about last transfer chain entry checksum mismatch, but got: %v", err)
	}

}

// TestVerifyEnvelope_SenderPlatformMismatch tests that transfer chain entries signed by a platform
// claiming to be a different platform are rejected.
// This test verifies that the platform validation in verifyEnvelopeTransferChain correctly detects
// when a platform signs an entry but claims a different eblPlatform.
func TestVerifyEnvelope_SenderPlatformMismatch(t *testing.T) {
	// Load the valid test envelope (Ed25519: sender claims to be EBL1, recipient=EBL2)
	envelope, err := loadEnvelopeFromFile(t, validEnvelopePath)
	if err != nil {
		t.Fatalf("Failed to load test envelope: %v", err)
	}

	// Load keys
	publicKey, err := crypto.ReadPublicKeyFromJWKFile(validPublicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read public key: %v", err)
	}

	carrierPublicKey, err := crypto.ReadPublicKeyFromJWKFile(validCarrierPublicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read carrier public key: %v", err)
	}

	rootCAs, err := testutil.LoadTestRootCA(validRootCAPath)
	if err != nil {
		t.Fatalf("Failed to load root CA: %v", err)
	}

	// Extract KIDs from all transfer chain entries
	entry0Header, err := crypto.ParseJWSHeader(string(envelope.EnvelopeTransferChain[0]))
	if err != nil {
		t.Fatalf("Failed to parse entry 0 header: %v", err)
	}

	entry1Header, err := crypto.ParseJWSHeader(string(envelope.EnvelopeTransferChain[1]))
	if err != nil {
		t.Fatalf("Failed to parse entry 1 header: %v", err)
	}

	// Extract carrier KID from issuanceManifestSignedContent
	firstEntryPayload, err := testutil.DecodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
	if err != nil {
		t.Fatalf("Failed to decode first entry: %v", err)
	}

	issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string)
	if !ok {
		t.Fatal("issuanceManifestSignedContent not found")
	}

	carrierHeader, err := crypto.ParseJWSHeader(issuanceManifestRaw)
	if err != nil {
		t.Fatalf("Failed to parse carrier header: %v", err)
	}

	// Create mock key provider that returns the wrong platform for the last transfer chain entry
	// Both entries claim eblPlatform=EBL1, but we tell the mock that entry 1 was signed by EBL2
	// This simulates a platform trying to impersonate another platform
	keyProvider := testutil.NewMockKeyProvider()
	keyProvider.AddKeyWithPlatform(entry0Header.KeyID, publicKey, "EBL1")         // Correct
	keyProvider.AddKeyWithPlatform(entry1Header.KeyID, publicKey, "EBL2")         // WRONG - entry claims EBL1
	keyProvider.AddKeyWithPlatform(carrierHeader.KeyID, carrierPublicKey, "CAR1") // Correct

	// Verify - should fail during transfer chain validation
	input := EnvelopeVerificationInput{
		Envelope:              envelope,
		RootCAs:               rootCAs,
		KeyProvider:           keyProvider,
		RecipientPlatformCode: "EBL2", // Correct recipient
	}

	result, err := VerifyEnvelope(input)

	// Should get an error about platform mismatch in the transfer chain
	if err == nil {
		t.Fatal("Expected error about sender platform mismatch, got nil")
	}

	expectedErr := "entry 1 was signed by platform EBL2"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Expected error containing %q, got: %v", expectedErr, err)
	}

	// Should still return partial result for duplicate detection
	if result == nil {
		t.Error("Expected partial result even on error, got nil")
	} else if result.LastTransferChainEntrySignedContentChecksum == "" {
		t.Error("Expected LastEnvelopeTransferChainEntrySignedContentChecksum to be set in partial result")
	}

	t.Logf("Sender platform mismatch correctly detected: %v", err)
}

// loadValidTestEnvelope loads the valid test envelope from the test data file
func loadEnvelopeFromFile(t *testing.T, filePath string) (*EblEnvelope, error) {
	t.Helper()
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read envelope file: %w", err)
	}

	var envelope EblEnvelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse envelope: %w", err)
	}

	return &envelope, nil
}

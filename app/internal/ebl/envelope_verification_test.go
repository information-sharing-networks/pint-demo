package ebl

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// mockKeyProvider is a simple test helper that implements jws.KeyProvider
// It returns keys from a map based on the KID in the JWS header
type mockKeyProvider struct {
	keys map[string]any // map of KID -> public key
}

func newMockKeyProvider() *mockKeyProvider {
	return &mockKeyProvider{
		keys: make(map[string]any),
	}
}

func (m *mockKeyProvider) addKey(kid string, key any) {
	m.keys[kid] = key
}

func (m *mockKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	kid, ok := sig.ProtectedHeaders().KeyID()
	if !ok || kid == "" {
		return fmt.Errorf("kid is required in JWS header")
	}

	alg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return fmt.Errorf("alg is required in JWS header")
	}

	key, exists := m.keys[kid]
	if !exists {
		return fmt.Errorf("key not found for kid: %s", kid)
	}

	sink.Key(alg, key)
	return nil
}

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
	}{
		{
			name:                  "valid_Ed25519",
			eblEnvelopePath:       "../crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json",
			publicKeyJWKPath:      "../crypto/testdata/keys/ed25519-eblplatform.example.com.public.jwk",
			carrierPublicKeyPath:  "../crypto/testdata/keys/ed25519-carrier.example.com.public.jwk",
			rootCACertPath:        "../crypto/testdata/certs/root-ca.crt", // all the test certs are signed by the same root CA
			expectedSenderDomain:  "ed25519-eblplatform.example.com",
			expectedCarrierDomain: "ed25519-carrier.example.com",
		},
		{
			name:                  "valid_RSA",
			eblEnvelopePath:       "../crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-rsa.json",
			publicKeyJWKPath:      "../crypto/testdata/keys/rsa-eblplatform.example.com.public.jwk",
			carrierPublicKeyPath:  "../crypto/testdata/keys/rsa-carrier.example.com.public.jwk",
			rootCACertPath:        "../crypto/testdata/certs/root-ca.crt",
			expectedSenderDomain:  "rsa-eblplatform.example.com",
			expectedCarrierDomain: "rsa-carrier.example.com",
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
			rootCAs, err := LoadTestRootCA(test.rootCACertPath)
			if err != nil {
				t.Fatalf("Failed to load root CA: %v", err)
			}

			// Extract KIDs from the JWS headers to populate the mock KeyProvider
			senderHeader, err := crypto.ParseHeader(string(envelope.EnvelopeManifestSignedContent))
			if err != nil {
				t.Fatalf("Failed to parse sender JWS header: %v", err)
			}

			// Extract carrier KID from first transfer chain entry
			firstEntryPayload, err := decodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
			if err != nil {
				t.Fatalf("Failed to decode first transfer chain entry: %v", err)
			}

			// Get issuanceManifestSignedContent from the first entry
			issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string)
			if !ok {
				t.Fatalf("issuanceManifestSignedContent not found in first transfer chain entry")
			}

			carrierHeader, err := crypto.ParseHeader(issuanceManifestRaw)
			if err != nil {
				t.Fatalf("Failed to parse carrier JWS header: %v", err)
			}

			// Create mock KeyProvider with both keys
			keyProvider := newMockKeyProvider()
			keyProvider.addKey(senderHeader.KeyID, publicKey)
			keyProvider.addKey(carrierHeader.KeyID, carrierPublicKey)

			// Create verification input
			input := EnvelopeVerificationInput{
				Envelope:    &envelope,
				RootCAs:     rootCAs,
				KeyProvider: keyProvider,
			}

			// Verify the envelope
			result, err := VerifyEnvelopeTransfer(input)
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
	validEnvelopePath         = "../crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json"
	validPublicKeyPath        = "../crypto/testdata/keys/ed25519-eblplatform.example.com.public.jwk"
	validCarrierPublicKeyPath = "../crypto/testdata/keys/ed25519-carrier.example.com.public.jwk"
	validPrivateKeyPath       = "../crypto/testdata/keys/ed25519-eblplatform.example.com.private.jwk"
	validFullChainPath        = "../crypto/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt"
	validRootCAPath           = "../crypto/testdata/certs/root-ca.crt"
	validDomain               = "ed25519-eblplatform.example.com"
	wrongPublicKeyPath        = "../crypto/testdata/keys/rsa-eblplatform.example.com.public.jwk"
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
			name:            "incorrect public key",
			publicKeyPath:   wrongPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BSIG",
			wantErrContains: "JWS verification failed", // Signature fails before x5c check
		},
		{
			name: "tampered envelope manifest - signature invalid",
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
			name:            "wrong root CA",
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  true,
			wantErrCode:     "BSIG",
			wantErrContains: "certificate chain validation failed",
		},
		// Envelope integrity errors
		{
			name: "tampered transfer chain entry signature",
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
			wantErrContains: "checksum mismatch",
		},
		{
			name: "tampered transport document",
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
			name: "missing transportDocumentReference",
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
			name: "empty transfer chain",
			tamperEnvelope: func(env *EblEnvelope) error {
				env.EnvelopeTransferChain = []EnvelopeTransferChainEntrySignedContent{}
				return nil
			},
			publicKeyPath:   validPublicKeyPath,
			domain:          validDomain,
			useWrongCAPath:  false,
			wantErrCode:     "BENV",
			wantErrContains: "at least one entry",
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

			rootCAs, err := LoadTestRootCA(validRootCAPath)
			if err != nil {
				t.Fatalf("Failed to load root CA: %v", err)
			}
			if tt.useWrongCAPath {
				rootCAs = nil // this will make the verification function use system roots
			}

			// Extract KIDs and create mock KeyProvider
			keyProvider := newMockKeyProvider()

			// Only extract KIDs if the envelope has the required fields
			// (some tests intentionally create invalid envelopes)
			if len(envelope.EnvelopeManifestSignedContent) > 0 {
				senderHeader, err := crypto.ParseHeader(string(envelope.EnvelopeManifestSignedContent))
				if err == nil {
					keyProvider.addKey(senderHeader.KeyID, publicKey)
				}
			}

			if len(envelope.EnvelopeTransferChain) > 0 {
				firstEntryPayload, err := decodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
				if err == nil {
					if issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string); ok {
						carrierHeader, err := crypto.ParseHeader(issuanceManifestRaw)
						if err == nil {
							keyProvider.addKey(carrierHeader.KeyID, carrierPublicKey)
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
			_, err = VerifyEnvelopeTransfer(input)

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
	envelope, err := loadValidTestEnvelope()
	if err != nil {
		t.Fatalf("failed to load valid envelope: %v", err)
	}

	if len(envelope.EnvelopeTransferChain) < 2 {
		t.Fatalf("test envelope must have at least 2 transfer chain entries")
	}

	// Decode the second entry's payload
	secondEntryPayload, err := decodeJWSPayload(string(envelope.EnvelopeTransferChain[1]))
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
	rootCAs, err := LoadTestRootCA(validRootCAPath)
	if err != nil {
		t.Fatalf("Failed to load root CA: %v", err)
	}

	// Get carrier public key
	carrierPublicKey, err := crypto.ReadPublicKeyFromJWKFile(validCarrierPublicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read carrier public key: %v", err)
	}

	// Extract KIDs and create mock KeyProvider
	senderHeader, err := crypto.ParseHeader(string(envelope.EnvelopeManifestSignedContent))
	if err != nil {
		t.Fatalf("Failed to parse sender JWS header: %v", err)
	}

	firstEntryPayload, err := decodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
	if err != nil {
		t.Fatalf("Failed to decode first transfer chain entry: %v", err)
	}

	issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string)
	if !ok {
		t.Fatalf("issuanceManifestSignedContent not found in first transfer chain entry")
	}

	carrierHeader, err := crypto.ParseHeader(issuanceManifestRaw)
	if err != nil {
		t.Fatalf("Failed to parse carrier JWS header: %v", err)
	}

	keyProvider := newMockKeyProvider()
	keyProvider.addKey(senderHeader.KeyID, privateKey.Public())
	keyProvider.addKey(carrierHeader.KeyID, carrierPublicKey)

	// Verify the envelope - should fail
	input := EnvelopeVerificationInput{
		Envelope:    envelope,
		RootCAs:     rootCAs,
		KeyProvider: keyProvider,
	}

	_, err = VerifyEnvelopeTransfer(input)
	if err == nil {
		t.Fatal("Expected verification to fail for broken chain link, but it succeeded")
	}

	// Check for expected error - should detect the broken chain link
	if !strings.Contains(err.Error(), "chain link broken") {
		t.Errorf("Expected error about broken chain link, but got: %v", err)
	}
}

// TestVerifyEnvelopeTransfer_ManifestPointsToWrongEntry tests that verification detects
// when the manifest's lastEnvelopeTransferChainEntrySignedContentChecksum does not
// match the final entry in the transfer chain.
func TestVerifyEnvelopeTransfer_ManifestPointsToWrongEntry(t *testing.T) {

	// Load test keys and certs
	privateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile(validPrivateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	certChain, err := crypto.ReadCertChainFromPEMFile(validFullChainPath)
	if err != nil {
		t.Fatalf("Failed to read cert chain: %v", err)
	}

	envelope, err := loadValidTestEnvelope()
	if err != nil {
		t.Fatalf("failed to load valid envelope: %v", err)
	}

	if len(envelope.EnvelopeTransferChain) < 2 {
		t.Fatalf("test envelope must have at least 2 transfer chain entries")
	}

	// Create a new manifest pointing to the wrong entry (first instead of last)
	transportDocJSON, err := json.Marshal(envelope.TransportDocument)
	if err != nil {
		t.Fatalf("failed to marshal transport document: %v", err)
	}

	envelopeManifest, err := NewEnvelopeManifestBuilder().
		WithTransportDocument(transportDocJSON).
		WithLastTransferChainEntry(envelope.EnvelopeTransferChain[0]). // should be [1]
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
	rootCAs, err := LoadTestRootCA(validRootCAPath)
	if err != nil {
		t.Fatalf("Failed to load root CA: %v", err)
	}

	// Get carrier public key
	carrierPublicKey, err := crypto.ReadPublicKeyFromJWKFile(validCarrierPublicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read carrier public key: %v", err)
	}

	// Extract KIDs and create mock KeyProvider
	senderHeader, err := crypto.ParseHeader(string(envelope.EnvelopeManifestSignedContent))
	if err != nil {
		t.Fatalf("Failed to parse sender JWS header: %v", err)
	}

	firstEntryPayload, err := decodeJWSPayload(string(envelope.EnvelopeTransferChain[0]))
	if err != nil {
		t.Fatalf("Failed to decode first transfer chain entry: %v", err)
	}

	issuanceManifestRaw, ok := firstEntryPayload["issuanceManifestSignedContent"].(string)
	if !ok {
		t.Fatalf("issuanceManifestSignedContent not found in first transfer chain entry")
	}

	carrierHeader, err := crypto.ParseHeader(issuanceManifestRaw)
	if err != nil {
		t.Fatalf("Failed to parse carrier JWS header: %v", err)
	}

	keyProvider := newMockKeyProvider()
	keyProvider.addKey(senderHeader.KeyID, privateKey.Public())
	keyProvider.addKey(carrierHeader.KeyID, carrierPublicKey)

	// Verify the envelope - should fail
	input := EnvelopeVerificationInput{
		Envelope:    envelope,
		RootCAs:     rootCAs,
		KeyProvider: keyProvider,
	}

	_, err = VerifyEnvelopeTransfer(input)
	if err == nil {
		t.Fatal("Expected verification to fail for wrong manifest checksum, but it succeeded")
	}

	// Check for expected error
	if !strings.Contains(err.Error(), "last transfer chain entry checksum mismatch") {
		t.Errorf("Expected error about last transfer chain entry checksum mismatch, but got: %v", err)
	}

}

// loadValidTestEnvelope loads the valid test envelope from the test data file
func loadValidTestEnvelope() (*EblEnvelope, error) {
	envelopeBytes, err := os.ReadFile(validEnvelopePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read envelope file: %w", err)
	}

	var envelope EblEnvelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse envelope: %w", err)
	}

	return &envelope, nil
}

// decodeJWSPayload decodes the payload from a JWS string (header.payload.signature)
func decodeJWSPayload(jws string) (map[string]any, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	return payload, nil
}

func LoadTestRootCA(certPath string) (*x509.CertPool, error) {

	// get public key from root CA cert
	certChain, err := crypto.ReadCertChainFromPEMFile(certPath)

	if err != nil {
		return nil, fmt.Errorf("failed to read test certificate chain: %v", err)
	}

	if len(certChain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	// Create a root cert pool contain the test root CA
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(certChain[0]) // the root CA is the only cert in root-ca.pem
	return rootCAs, nil
}

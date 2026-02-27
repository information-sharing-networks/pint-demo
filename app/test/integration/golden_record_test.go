//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl/testutil"
)

// TestGoldenRecord verifies that the PINT envelope creation pipeline
//
// the test reconstructs a known two-entry transfer chain (ISSU + TRNS) from the testdata files,
// signs each entry with the same keys used to produce the stored golden envelope.
//
// The tests then check two things:
//
//  1. VerifyEnvelope accepts the result (confirms structure, signatures etc)
//
//  2. The recreated JWS tokens match the stored golden envelope byte-for-byte
//     Note this test relies on using a deterministc signing algorithm (Ed25519 in this case)
//
// The testdata pins all variable inputs: transaction data, actionDateTime, and transport document.
// The golden envelope file (HHL71800000-ebl-envelope-ed25519.json) is the reference output.
func TestGoldenRecord(t *testing.T) {

	// Step 1: load the signing keys and cert chains used to produce the golden record
	car1PrivateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../testdata/keys/ed25519-carrier.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}
	car1CertChain, err := crypto.ReadCertChainFromPEMFile("../testdata/certs/ed25519-carrier.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Failed to read cert chain: %v", err)
	}

	ebl1PrivateKey, err := crypto.ReadEd25519PrivateKeyFromJWKFile("../testdata/keys/ed25519-eblplatform.example.com.private.jwk")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}
	ebl1CertChain, err := crypto.ReadCertChainFromPEMFile("../testdata/certs/ed25519-eblplatform.example.com-fullchain.crt")
	if err != nil {
		t.Fatalf("Failed to read cert chain: %v", err)
	}

	car1KeyId, err := crypto.GenerateKeyIDFromEd25519Key(car1PrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("Failed to generate key ID: %v", err)
	}

	ebl1KeyId, err := crypto.GenerateKeyIDFromEd25519Key(ebl1PrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("Failed to generate key ID: %v", err)
	}

	// Step 2: Setup the key provider
	keyProvider := testutil.NewMockKeyProvider()
	keyProvider.AddKeyWithPlatform(car1KeyId, car1PrivateKey.Public(), "CAR1")
	keyProvider.AddKeyWithPlatform(ebl1KeyId, ebl1PrivateKey.Public(), "EBL1")

	issueEntryFilePath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-ISSU-ed25519.json"
	origIssuanceTransaction, origIssuancePlatform := reconstructTransactionFromEntryFile(t, issueEntryFilePath)
	trnsEntryFilePath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
	origTransferTransaction, origTransferPlatform := reconstructTransactionFromEntryFile(t, trnsEntryFilePath)

	// Step 3: load the test root CA so VerifyEnvelope can validate the certificate chains
	rootCAs, err := crypto.LoadCustomRootCAs("../testdata/certs/root-ca.crt")
	if err != nil {
		t.Fatalf("Failed to load root CA: %v", err)
	}

	// Step 4: load the transport document and issuance manifest from testdata files.
	// these are fixed inputs — changing either would change the transport document checksum
	// and break the comparison.
	issuanceDocumentRecordPath := "../testdata/issuance-documents/HHL71800000-unsigned.json"
	issuanceDocumentRecordData, err := os.ReadFile(issuanceDocumentRecordPath)
	if err != nil {
		t.Fatalf("Failed to read issuance record: %v", err)
	}
	var issuanceRecord map[string]json.RawMessage
	if err := json.Unmarshal(issuanceDocumentRecordData, &issuanceRecord); err != nil {
		t.Fatalf("Failed to parse issuance record: %v", err)
	}

	transportDocument := ebl.TransportDocument(issuanceRecord["document"])

	transportDocumentChecksum, err := transportDocument.Checksum()
	if err != nil {
		t.Fatalf("Failed to compute transport document checksum: %v", err)
	}

	issuanceManifestPath := "../testdata/issuance-documents/HHL71800000-issuance-manifest.json"
	issuanceManifestData, err := os.ReadFile(issuanceManifestPath)
	if err != nil {
		t.Fatalf("Failed to read issuance manifest: %v", err)
	}

	var origIssuanceManifest ebl.IssuanceManifest
	if err := json.Unmarshal(issuanceManifestData, &origIssuanceManifest); err != nil {
		t.Fatalf("Failed to parse issuance manifest: %v", err)
	}
	issueToChecksum := ebl.IssueToChecksum(origIssuanceManifest.IssueToChecksum)
	eblVisualisationChecksum := origIssuanceManifest.EBLVisualisationByCarrierChecksum

	// Step 5: recreate the issuance manifest and sign it with the carrier key
	iBuilder := ebl.NewIssuanceManifestBuilder().
		WithDocumentChecksum(transportDocumentChecksum).
		WitheBLVisualisationByCarrierChecksum(*eblVisualisationChecksum).
		WithIssueTo(issueToChecksum)

	issuanceManifest, err := iBuilder.Build()
	if err != nil {
		t.Fatalf("could not create issuance manifest %v", err)
	}

	issuanceManifestJWS, err := issuanceManifest.Sign(car1PrivateKey, car1CertChain)
	if err != nil {
		t.Fatal("could not sign issuance manifest")
	}

	// Step 5: recreate the ISSUE transaction
	// using the builder functions rather than copying the raw structs, as this exercises the same code path as production.
	actor := origIssuanceTransaction.Actor
	recipient := *origIssuanceTransaction.Recipient

	// use the original actionDateTime to keep the signing input deterministic
	issuanceDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", origIssuanceTransaction.ActionDateTime)
	if err != nil {
		t.Fatalf("Failed to parse issuance action date time: %v", err)
	}
	issuanceTransaction := ebl.CreateIssueTransaction(actor, recipient, issuanceDateTime)

	issuanceEntryBuilder := ebl.NewEnvelopeTransferChainEntryBuilder(true).
		WithTransportDocumentChecksum(transportDocumentChecksum).
		WithEBLPlatform(origIssuancePlatform).
		WithIssuanceManifestSignedContent(issuanceManifestJWS).
		WithTransaction(issuanceTransaction)

	issuanceEntry, err := issuanceEntryBuilder.Build()
	if err != nil {
		t.Fatalf("could not build issuance entry %v", err)
	}

	issuanceEntryJWS, err := issuanceEntry.Sign(car1PrivateKey, car1CertChain)
	if err != nil {
		t.Fatal("could not sign issuance entry")
	}
	issuanceEntryChekcsum, err := issuanceEntryJWS.Checksum()
	if err != nil {
		t.Fatalf("could not compute issuance entry checksum %v", err)
	}

	// Step 6: recreate the TRANSFER transaction
	actor = origTransferTransaction.Actor
	recipient = *origTransferTransaction.Recipient

	transferDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", origTransferTransaction.ActionDateTime)
	if err != nil {
		t.Fatalf("Failed to parse transfer action date time: %v", err)
	}
	trnsTransaction := ebl.CreateTransferTransaction(actor, recipient, transferDateTime)
	trnsEntryBuilder := ebl.NewEnvelopeTransferChainEntryBuilder(false).
		WithTransportDocumentChecksum(transportDocumentChecksum).
		WithEBLPlatform(origTransferPlatform).
		WithPreviousEnvelopeTransferChainEntrySignedContentChecksum(issuanceEntryChekcsum).
		WithTransaction(trnsTransaction)
	trnsEntry, err := trnsEntryBuilder.Build()
	if err != nil {
		t.Fatalf("could not build transfer chain entry %v", err)
	}

	trnsEntryJWS, err := trnsEntry.Sign(ebl1PrivateKey, ebl1CertChain)
	if err != nil {
		t.Fatal("could not sign transfer chain entry")
	}

	// Step 7: build and sign the envelope manifest, then assemble the full envelope
	mBuilder := ebl.NewEnvelopeManifestBuilder().
		WithTransportDocument(transportDocument).
		WithLastTransferChainEntry(issuanceEntryJWS).
		WithLastTransferChainEntry(trnsEntryJWS)
	envelopeManifest, err := mBuilder.Build()
	if err != nil {
		t.Fatal("could not build envelope manifest")
	}

	envelopeManifestJWS, err := envelopeManifest.Sign(ebl1PrivateKey, ebl1CertChain)
	if err != nil {
		t.Fatal("could not sign envelope manifest")
	}

	eBuilder := ebl.NewEnvelopeBuilder()

	eBuilder.WithTransportDocument(transportDocument).
		WithEnvelopeManifestSignedContent(envelopeManifestJWS).
		AddTransferChainEntry(issuanceEntryJWS).
		AddTransferChainEntry(trnsEntryJWS)

	envelope, err := eBuilder.Build()
	if err != nil {
		t.Fatalf("could not build envelope %v", err)
	}

	// Step 8: VerifyEnvelope checks structural correctness, certificate trust, and every signature in the chain
	recipientPlatformCode := "EBL2"
	result, err := ebl.VerifyEnvelope(context.Background(), ebl.EnvelopeVerificationInput{
		Envelope:              envelope,
		RootCAs:               rootCAs,
		KeyProvider:           keyProvider,
		RecipientPlatformCode: recipientPlatformCode,
	})
	if err != nil {
		t.Fatalf("could not verify envelope %v", err)
	}
	if result.Manifest == nil {
		t.Fatalf("Expected manifest to be extracted, but got nil")
	}
	if result.Manifest.TransportDocumentChecksum != transportDocumentChecksum {
		t.Errorf("manifest transport document checksum mismatch: got %s, want %s", result.Manifest.TransportDocumentChecksum, transportDocumentChecksum)
	}
	if len(result.TransferChain) != 2 {
		t.Errorf("TransferChain length: got %d, want 2", len(result.TransferChain))
	}
	if result.TransportDocumentReference != "HHL71800000" {
		t.Errorf("TransportDocumentReference: got %s, want HHL71800000", result.TransportDocumentReference)
	}
	if result.ActionCode != origTransferTransaction.ActionCode {
		t.Errorf("ActionCode: got %s, want %s", result.ActionCode, origTransferTransaction.ActionCode)
	}
	if result.SenderPlatform != origTransferPlatform {
		t.Errorf("SenderPlatform: got %s, want %s", result.SenderPlatform, origTransferPlatform)
	}
	if result.RecipientPlatform != recipientPlatformCode {
		t.Errorf("RecipientPlatform: got %s, want %s", result.RecipientPlatform, recipientPlatformCode)
	}
	if result.TrustLevel != crypto.TrustLevelEVOV {
		t.Errorf("TrustLevel: got %v, want %v", result.TrustLevel, crypto.TrustLevelEVOV)
	}

	// Step 9: compare recreated JWS tokens  against the golden envelope.
	goldenEnvelopeData, err := os.ReadFile("../testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json")
	if err != nil {
		t.Fatalf("Failed to read golden envelope: %v", err)
	}
	var goldenEnvelope ebl.Envelope
	if err := json.Unmarshal(goldenEnvelopeData, &goldenEnvelope); err != nil {
		t.Fatalf("Failed to parse golden envelope: %v", err)
	}
	if len(goldenEnvelope.EnvelopeTransferChain) != 2 {
		t.Fatalf("Golden envelope expected 2 transfer chain entries, got %d", len(goldenEnvelope.EnvelopeTransferChain))
	}

	if issuanceEntryJWS != goldenEnvelope.EnvelopeTransferChain[0] {
		t.Errorf("ISSU transfer chain entry JWS does not match golden record")
	}
	if trnsEntryJWS != goldenEnvelope.EnvelopeTransferChain[1] {
		t.Errorf("TRNS transfer chain entry JWS does not match golden record")
	}

	t.Log("Golden record test passed - sucessfully recreated HHL71800000-ebl-envelope-ed25519.json")
}

// reconstructTransactionFromEntryFile reads a fixture file containing a single-transaction transfer
// chain entry and returns the transaction and the platform code. The returned transaction preserves
// the original actionDateTime and action code, keeping signing inputs deterministic.
func reconstructTransactionFromEntryFile(t *testing.T, filePath string) (ebl.Transaction, string) {
	t.Helper()
	transferChainEntryData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read last transfer chain entry: %v", err)
	}
	var transferChainEntry ebl.EnvelopeTransferChainEntry
	if err := json.Unmarshal(transferChainEntryData, &transferChainEntry); err != nil {
		t.Fatalf("Failed to parse last transfer chain entry: %v", err)
	}

	return transferChainEntry.Transactions[0], transferChainEntry.EblPlatform
}

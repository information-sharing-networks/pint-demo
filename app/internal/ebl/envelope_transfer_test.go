package ebl

import (
	"encoding/json"
	"log"
	"os"
	"testing"
)

// TestRecreateSampleEblEnvelope tests that we can recreate the sample ebl envelope in testdata/pint-transfers
// this is a sanity check to confirm we can correctly recreate the manually computed signatures and checksums in the sample data
func TestRecreateSampleEblEnvelope(t *testing.T) {

	// create the transfer chain entries and signatures and check these match the sampe entries in the sample ebl envelope (eblEnvelope.EnvelopeTransferChain)
	testData := []struct {
		name                                 string
		privateKeyJWKPath                    string
		certChainFilePath                    string
		sampleTransferChainEntryIssuePath    string
		sampleTransferChainEntryTransferPath string
		sampleEblEnvelopePath                string
	}{
		{
			name:                                 "eblEnvelope_Ed25519",
			privateKeyJWKPath:                    "../crypto/testdata/keys/ed25519-eblplatform.example.com.private.jwk",
			certChainFilePath:                    "../crypto/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt",
			sampleTransferChainEntryIssuePath:    "../crypto/testdata/pint-transfers/HHL71800000-transfer-chain-entry-ISSU-ed25519.json",
			sampleEblEnvelopePath:                "../crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json",
			sampleTransferChainEntryTransferPath: "../crypto/testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json",
		},
		{
			name:                                 "eblEnvelope_RSA",
			privateKeyJWKPath:                    "../crypto/testdata/keys/rsa-eblplatform.example.com.private.jwk",
			certChainFilePath:                    "../crypto/testdata/certs/rsa-eblplatform.example.com-fullchain.crt",
			sampleTransferChainEntryIssuePath:    "../crypto/testdata/pint-transfers/HHL71800000-transfer-chain-entry-ISSU-rsa.json",
			sampleEblEnvelopePath:                "../crypto/testdata/pint-transfers/HHL71800000-ebl-envelope-rsa.json",
			sampleTransferChainEntryTransferPath: "../crypto/testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-rsa.json",
		},
	}
	for _, test := range testData {
		t.Run(test.name, func(t *testing.T) {

			// create the envelope transfer chain

			// read sample transfer chain entry
			issueData, err := os.ReadFile(test.sampleTransferChainEntryIssuePath)
			if err != nil {
				t.Fatalf("failed to read sample transfer chain entry: %v", err)
			}

			// unmarshal the sample transfer chain entry to get the transport document checksum and CTR
			sampleIssueEntry := &EnvelopeTransferChainEntry{}
			if err := json.Unmarshal(issueData, sampleIssueEntry); err != nil {
				t.Fatalf("failed to unmarshal sample transfer chain entry: %v", err)
			}

			// read the previous transfer chain entry
			transferData, err := os.ReadFile(test.sampleTransferChainEntryTransferPath)
			if err != nil {
				t.Fatalf("failed to read previous transfer chain entry: %v", err)
			}

			// unmarshal the transfer chain entry
			sampleTransferEntry := &EnvelopeTransferChainEntry{}
			if err := json.Unmarshal(transferData, sampleTransferEntry); err != nil {
				t.Fatalf("failed to unmarshal previous transfer chain entry: %v", err)
			}

			// create the transfer chain ISSUE entry input using the sample data
			issueTransferChainEntryInput := TransferChainEntryInput{
				TransportDocumentChecksum:     sampleIssueEntry.TransportDocumentChecksum,
				EBLPlatform:                   sampleIssueEntry.EblPlatform,
				IsFirstEntry:                  true,
				IssuanceManifestSignedContent: sampleIssueEntry.IssuanceManifestSignedContent,
				Transactions:                  sampleIssueEntry.Transactions,
			}

			// create the transfer chain entry
			signedIssueEntry, err := CreateTransferChainEntry(issueTransferChainEntryInput, test.privateKeyJWKPath, test.certChainFilePath)
			if err != nil {
				t.Fatalf("failed to create transfer chain entry: %v", err)
			}

			// create the transfer chain entry input for the transfer entry
			transferTransferChainEntryInput := TransferChainEntryInput{
				TransportDocumentChecksum: sampleTransferEntry.TransportDocumentChecksum,
				EBLPlatform:               sampleTransferEntry.EblPlatform,
				IsFirstEntry:              false,
				PreviousEnvelopeTransferChainEntrySignedContent: signedIssueEntry,
				Transactions: sampleTransferEntry.Transactions,
			}

			// create the transfer chain entry
			signedTransferEntry, err := CreateTransferChainEntry(transferTransferChainEntryInput, test.privateKeyJWKPath, test.certChainFilePath)
			if err != nil {
				t.Fatalf("failed to create transfer chain entry: %v", err)
			}

			// read the sample ebl envelope
			sampleEblEnvelopeData, err := os.ReadFile(test.sampleEblEnvelopePath)
			if err != nil {
				t.Fatalf("failed to read sample ebl envelope: %v", err)
			}

			sampleEblEnvelope := &EblEnvelope{}
			if err := json.Unmarshal(sampleEblEnvelopeData, sampleEblEnvelope); err != nil {
				t.Fatalf("failed to unmarshal sample ebl envelope: %v", err)
			}

			// recreate the ebl envelope using computed transfer chain entries and sample transport document and supporting documents
			envelope, err := CreateEnvelopeTransfer(EnvelopeTransferInput{
				TransportDocument: sampleEblEnvelope.TransportDocument,
				EnvelopeTransferChain: []EnvelopeTransferChainEntrySignedContent{
					signedIssueEntry,
					signedTransferEntry,
				},
				EBLVisualizationFilePath: "../crypto/testdata/transport-documents/HHL71800000.pdf",
				SupportingDocumentFilePaths: []string{
					"../crypto/testdata/pint-transfers/HHL71800000-invoice.pdf",
					"../crypto/testdata/pint-transfers/HHL71800000-packing-list.pdf",
				},
			}, test.privateKeyJWKPath, test.certChainFilePath)
			if err != nil {
				t.Fatalf("failed to create ebl envelope: %v", err)
			}

			// check the computed transfer chain entries match the sample
			if len(envelope.EnvelopeTransferChain) != len(sampleEblEnvelope.EnvelopeTransferChain) {
				t.Fatalf("transfer chain length mismatch")
			}

			for i := range envelope.EnvelopeTransferChain {
				if envelope.EnvelopeTransferChain[i] != sampleEblEnvelope.EnvelopeTransferChain[i] {
					t.Fatalf("transfer chain entry item %d mismatch", i)
				}
				log.Printf("Transfer chain entry item %d matches\n", i)
			}

			// check the computed ebl envelope matches the sample ebl envelope
			if envelope.EnvelopeManifestSignedContent != sampleEblEnvelope.EnvelopeManifestSignedContent {
				t.Fatalf("ebl envelope manifest mismatch")
			}

			log.Printf("EBL envelope manifest matches\n")
		})
	}

}

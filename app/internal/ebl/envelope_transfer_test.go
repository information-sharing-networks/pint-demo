package ebl

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

func TestCreateEnvelope(t *testing.T) {
	testData := []struct {
		name                 string
		privateKeyJWKPath    string
		certChainFilePath    string
		receivedEnvelopePath string
	}{
		{
			name:                 "forward_Ed25519",
			privateKeyJWKPath:    "../../test/testdata/keys/ed25519-eblplatform.example.com.private.jwk",
			certChainFilePath:    "../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt",
			receivedEnvelopePath: "../../test/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json",
		},
	}

	for _, test := range testData {
		t.Run(test.name, func(t *testing.T) {
			// Load the received envelope
			sampleEnvelopeData, err := os.ReadFile(test.receivedEnvelopePath)
			if err != nil {
				t.Fatalf("failed to read sample ebl envelope: %v", err)
			}

			receivedEnvelope := &Envelope{}
			if err := json.Unmarshal(sampleEnvelopeData, receivedEnvelope); err != nil {
				t.Fatalf("failed to unmarshal sample ebl envelope: %v", err)
			}

			// Load the private key and certificate chain
			privateKey, err := crypto.ReadPrivateKeyFromJWKFile(test.privateKeyJWKPath)
			if err != nil {
				t.Fatalf("failed to load private key: %v", err)
			}

			certChain, err := crypto.ReadCertChainFromPEMFile(test.certChainFilePath)
			if err != nil {
				t.Fatalf("failed to load certificate chain: %v", err)
			}

			// Create a new transaction
			newTransaction := CreateTransferTransaction(
				ActorParty{
					PartyName:   "Test Platform B",
					EblPlatform: "TEST",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "TEST",
							PartyCode:        "PLATFORM_B",
						},
					},
				},
				RecipientParty{
					PartyName:   "Test Platform C",
					EblPlatform: "TEST",
					IdentifyingCodes: []IdentifyingCode{
						{
							CodeListProvider: "TEST",
							PartyCode:        "PLATFORM_C",
						},
					},
				},
			)

			// Create a new transfer chain entry from the transaction
			newEntry, err := CreateTransferChainEntry(
				receivedEnvelope,
				[]Transaction{newTransaction},
				"TEST",
				privateKey,
				certChain,
			)
			if err != nil {
				t.Fatalf("failed to create transfer chain entry: %v", err)
			}

			// Create envelope with the new entry
			input := CreateEnvelopeInput{
				ReceivedEnvelope:                   receivedEnvelope,
				NewTransferChainEntrySignedContent: &newEntry,
			}
			forwardEnvelope, err := CreateEnvelope(input, privateKey, certChain)
			if err != nil {
				t.Fatalf("failed to create envelope with entry: %v", err)
			}

			// Verify the transfer chain has one more entry
			if len(forwardEnvelope.EnvelopeTransferChain) != len(receivedEnvelope.EnvelopeTransferChain)+1 {
				t.Fatalf("transfer chain length mismatch: got %d, want %d",
					len(forwardEnvelope.EnvelopeTransferChain),
					len(receivedEnvelope.EnvelopeTransferChain)+1)
			}

			// Verify the old entries are unchanged
			for i := 0; i < len(receivedEnvelope.EnvelopeTransferChain); i++ {
				if forwardEnvelope.EnvelopeTransferChain[i] != receivedEnvelope.EnvelopeTransferChain[i] {
					t.Fatalf("transfer chain entry %d was modified", i)
				}
			}

			// Verify the transport document is unchanged
			if string(forwardEnvelope.TransportDocument) != string(receivedEnvelope.TransportDocument) {
				t.Fatalf("transport document was modified")
			}

			// Verify the new manifest is valid
			if forwardEnvelope.EnvelopeManifestSignedContent == "" {
				t.Fatalf("envelope manifest is empty")
			}

			log.Printf("Successfully forwarded envelope with new entry\n")
		})
	}
}

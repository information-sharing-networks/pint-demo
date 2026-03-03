package ebl

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/information-sharing-networks/pint-demo/app/internal/crypto"
)

// TestCreateEnvelopeForDelivery covers building a forwarding envelope by appending a new transfer chain entry to a received envelope.
func TestCreateEnvelopeForDelivery(t *testing.T) {
	// debug
	t.Skip("debug")
	tests := []struct {
		name                 string
		privateKeyJWKPath    string
		certChainFilePath    string
		receivedEnvelopePath string
		eblPlatform          string
	}{
		{
			name:                 "forward_Ed25519",
			privateKeyJWKPath:    "../../test/testdata/keys/ed25519-eblplatform.example.com.private.jwk",
			certChainFilePath:    "../../test/testdata/certs/ed25519-eblplatform.example.com-fullchain.crt",
			receivedEnvelopePath: "../../test/testdata/pint-transfers/HHL71800000-ebl-envelope-ed25519.json",
			eblPlatform:          "EBL1",
		},
	}

	for _, test := range tests {
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

			// creat a new actor party
			actorParty, err := NewActorPartyBuilder("Test Platform B", "TEST").
				WithIdentifyingCode("TEST", "PLATFORM_B", nil).
				Build()
			if err != nil {
				t.Fatalf("failed to create actor party: %v", err)
			}
			recipientParty, err := NewRecipientPartyBuilder("Test Platform C", "TEST").
				WithIdentifyingCode("TEST", "PLATFORM_C", nil).
				Build()
			if err != nil {
				t.Fatalf("failed to create recipient party: %v", err)
			}
			// Create a new transaction
			newTransaction := CreateTransferTransaction(
				actorParty,
				recipientParty,
				time.Time{},
			)

			// Create envelope with the new entry
			input := CreateEnvelopeInput{
				ReceivedEnvelope: receivedEnvelope,
				NewTransactions:  []Transaction{newTransaction},
			}
			forwardEnvelope, err := CreateEnvelopeForDelivery(input, privateKey, certChain, test.eblPlatform)
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
		})
	}
}

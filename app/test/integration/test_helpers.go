//go:build integration

// functions that are useful in integration tests

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/ebl"
	"github.com/information-sharing-networks/pint-demo/app/internal/pint"
	"github.com/jackc/pgx/v5/pgxpool"
)

// decodeSignedFinishedResponse decodes a SignedEnvelopeTransferFinishedResponse
// and returns the payload (assumes the signature is valid).
// the SigneEnvelopeTransferFinishedResponse is returned by the start envelope API when it processes a  DUPE, RECE, BSIG, BENV responses
func decodeSignedFinishedResponse(t *testing.T, SignedResponse pint.SignedEnvelopeTransferFinishedResponse) pint.EnvelopeTransferFinishedResponse {
	t.Helper()

	// JWS format is header.payload.signature
	parts := strings.Split(string(SignedResponse), ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode the base64url-encoded payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode JWS payload: %v", err)
	}

	// Unmarshal the JSON payload
	var payload pint.EnvelopeTransferFinishedResponse
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	return payload
}

type testIdentifyingCode struct {
	codeListProvider string
	partyCode        string
	codeListName     *string
}

// Helper to create a party with codes - reusable but not automatic
func createTestParty(t *testing.T, queries *database.Queries, partyName string, active bool, codes []testIdentifyingCode) database.Party {
	t.Helper()
	ctx := context.Background()

	party, err := queries.CreateParty(ctx, database.CreatePartyParams{
		PartyName: partyName,
		Active:    active,
	})
	if err != nil {
		t.Fatalf("failed to create test party: %v", err)
	}

	// create the party identifying codes
	for _, code := range codes {
		_, err = queries.CreatePartyIdentifyingCode(ctx, database.CreatePartyIdentifyingCodeParams{
			PartyID:          party.ID,
			CodeListProvider: code.codeListProvider,
			PartyCode:        code.partyCode,
			CodeListName:     code.codeListName,
		})
		if err != nil {
			t.Fatalf("failed to create party code: %v", err)
		}
	}

	return party
}

// cleanupDatabase truncates the envelope tables to reset the database state between tests
func cleanupDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		TRUNCATE TABLE transport_documents CASCADE;
		TRUNCATE TABLE parties CASCADE;
	`)
	if err != nil {
		t.Fatalf("Failed to cleanup database: %v", err)
	}
}

// create the test parties referenced in the test last transfer chains entry contained in the test ed25519 envelope
// c.f HHL71800000-transfer-chain-entry-TRNS-ed25519.json
func createValidParties(t *testing.T, testEnv *testEnv) {
	t.Helper()
	lastTransferChainEntryPath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
	lastTransferChainEntryData, err := os.ReadFile(lastTransferChainEntryPath)
	if err != nil {
		t.Fatalf("Failed to read last transfer chain entry: %v", err)
	}
	var lastTransferChainEntry ebl.EnvelopeTransferChainEntry
	if err := json.Unmarshal(lastTransferChainEntryData, &lastTransferChainEntry); err != nil {
		t.Fatalf("Failed to parse last transfer chain entry: %v", err)
	}

	recipientPartyName := lastTransferChainEntry.Transactions[0].Recipient.PartyName
	recipientIdentifyingCodes := lastTransferChainEntry.Transactions[0].Recipient.IdentifyingCodes

	// create the test party with the identifying codes listed in the sample data
	testIdentifyingCodes := make([]testIdentifyingCode, 0, len(recipientIdentifyingCodes))

	for _, identifyingcode := range recipientIdentifyingCodes {

		testIdentifyingCodes = append(testIdentifyingCodes, testIdentifyingCode{
			codeListProvider: identifyingcode.CodeListProvider,
			partyCode:        identifyingcode.PartyCode,
			codeListName:     identifyingcode.CodeListName,
		})
	}
	createTestParty(t, testEnv.queries, recipientPartyName, true, testIdentifyingCodes)

}

func returnValidParties(t *testing.T) (ebl.ActorParty, ebl.RecipientParty) {
	t.Helper()
	lastTransferChainEntryPath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
	lastTransferChainEntryData, err := os.ReadFile(lastTransferChainEntryPath)
	if err != nil {
		t.Fatalf("Failed to read last transfer chain entry: %v", err)
	}
	var lastTransferChainEntry ebl.EnvelopeTransferChainEntry
	if err := json.Unmarshal(lastTransferChainEntryData, &lastTransferChainEntry); err != nil {
		t.Fatalf("Failed to parse last transfer chain entry: %v", err)
	}

	return lastTransferChainEntry.Transactions[0].Actor, *lastTransferChainEntry.Transactions[0].Recipient

}

// create test party records where the recipient identifying codes resolve to different parties
func createInvalidParties(t *testing.T, testEnv *testEnv) {
	t.Helper()
	lastTransferChainEntryPath := "../testdata/pint-transfers/HHL71800000-transfer-chain-entry-TRNS-ed25519.json"
	lastTransferChainEntryData, err := os.ReadFile(lastTransferChainEntryPath)
	if err != nil {
		t.Fatalf("Failed to read last transfer chain entry: %v", err)
	}
	var lastTransferChainEntry ebl.EnvelopeTransferChainEntry
	if err := json.Unmarshal(lastTransferChainEntryData, &lastTransferChainEntry); err != nil {
		t.Fatalf("Failed to parse last transfer chain entry: %v", err)
	}

	recipientPartyName := lastTransferChainEntry.Transactions[0].Recipient.PartyName
	recipientIdentifyingCodes := lastTransferChainEntry.Transactions[0].Recipient.IdentifyingCodes

	// create the test party with the identifying codes listed in the sample data
	testIdentifyingCodes := make([]testIdentifyingCode, 0, len(recipientIdentifyingCodes))

	identityCode := recipientIdentifyingCodes[0]

	testIdentifyingCodes = append(testIdentifyingCodes, testIdentifyingCode{
		codeListProvider: identityCode.CodeListProvider,
		partyCode:        identityCode.PartyCode,
		codeListName:     identityCode.CodeListName,
	})
	createTestParty(t, testEnv.queries, recipientPartyName, true, testIdentifyingCodes)

	// create a second party using the second identifying code
	identityCode = recipientIdentifyingCodes[1]

	testIdentifyingCodes[0] = testIdentifyingCode{
		codeListProvider: identityCode.CodeListProvider,
		partyCode:        identityCode.PartyCode,
		codeListName:     identityCode.CodeListName,
	}

	createTestParty(t, testEnv.queries, "Different Party", true, testIdentifyingCodes)

}

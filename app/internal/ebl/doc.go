// Package ebl provides functions for creating and verifying DCSA PINT API envelopes.
//
// When forwarding envelopes to other platforms (via PINT client) use the CreateEnvelopeForDelivery() function.
//
// You can use the builders below if you need more control over the process:
//   - envelope.go: EnvelopeBuilder
//   - envelope_manifest.go: EnvelopeManifestBuilder
//   - envelope_transfer_chain.go: EnvelopeTransferChainEntryBuilder
//
// transaction.go: contains helper functions for creating transactions to be included in transfer chain entries.
//
// **state management**
// action_codes.go: contains the valid transitions between action codes - these rules apply to the sequence of transactions in the transfer chain
//
// there are a couple of state transitions that can only be determined when the transaction is processed by the platform.
// These are implemented inside the start_transfer handler (pint/handlers/start_transfer.go):
//   - already surrendered eBLs can't be transferred
//   - DISE detection (transfer chain inconsistent with existing transfer chain entries for this eBL)
package ebl

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
// pint/transport_document_state.go: contains the state machine for managing the state of an eBL as it is processed by the platform
package ebl

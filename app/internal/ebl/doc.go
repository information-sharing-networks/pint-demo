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
package ebl

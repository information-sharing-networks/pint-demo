// Package ebl provides functions for creating and verifying DCSA PINT API envelopes.
//
// For standard usage you should use the high level functions in envelope_transfer.go
//
// When forwarding envelopes to other platforms (via PINT client):
//  1. Create transactions using helpers:
//     - CreateTransferTransaction() etc
//  2. Package transactions into a transfer chain entry:
//     - CreateTransferChainEntry() - Creates a signed entry from your transactions
//  3. Create envelope with the new entry:
//     - CreateEnvelope() - Adds the entry to the chain and rebuilds the envelope
//  4. Marshal and send to next platform via PINT client (POST /v3/envelopes)
//
// The high level functions use the builders in this package to create the necessary structures:
//   - envelope.go: EnvelopeBuilder
//   - envelope.go: EnvelopeManifestBuilder
//   - transfer_chain.go: EnvelopeTransferChainEntryBuilder
//
// They can be used directly if you need more control over the process.
//
// # Note
//
// This package relies heavily on the crypto package. If tests fail,
// fix crypto issues first, then ebl failures.
package ebl

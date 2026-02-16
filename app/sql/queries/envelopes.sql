-- name: ExistsEnvelopeByLastChainEntryChecksum :one
-- Check if an transfer with this last_transfer_chain_entry_checksum already exists
SELECT EXISTS(
    SELECT 1 FROM envelopes 
    WHERE last_transfer_chain_entry_checksum = $1
);

-- name: GetEnvelopeByLastChainEntryChecksum :one
SELECT * FROM envelopes 
WHERE last_transfer_chain_entry_checksum = $1;

-- name: GetEnvelopeByReference :one
-- Get envelope by envelope reference (id)
SELECT * FROM envelopes 
WHERE id = $1;

-- name: CreateEnvelopeIfNew :one
-- Create a new envelope record for a transfer session if it doen't already exist for the current envelope state
INSERT INTO envelopes (
    id,
    created_at,
    updated_at,
    transport_document_checksum,
    envelope_state,
    sent_by_platform_code,
    last_transfer_chain_entry_checksum,
    envelope_manifest_signed_content,
    last_transfer_chain_entry_signed_content,
    trust_level
) VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    sqlc.arg(transport_document_checksum),
    sqlc.arg(envelope_state),
    sqlc.arg(sent_by_platform_code),
    sqlc.arg(last_transfer_chain_entry_checksum),
    sqlc.arg(envelope_manifest_signed_content),
    sqlc.arg(last_transfer_chain_entry_signed_content),
    sqlc.arg(trust_level)
) ON CONFLICT (last_transfer_chain_entry_checksum, envelope_state) DO NOTHING RETURNING *;

-- name: MarkEnvelopeAccepted :exec
-- Mark an envelope as accepted by setting accepted_at timestamp
UPDATE envelopes
SET accepted_at = NOW()
WHERE id = $1 AND accepted_at IS NULL;


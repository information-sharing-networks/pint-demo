-- name: GetEnvelopeByReference :one
-- Get envelope by envelope reference (id)
SELECT * FROM envelopes 
WHERE id = $1;

-- name: ExistsEnvelopeByLastChainEntrySignedContentPayloadChecksum :one
-- last_transfer_chain_entry_signed_content_payload_checksum is the checksum of the payload of the last transfer chain entry JWS token
-- and is unique for each transfer attempt
SELECT EXISTS(
    SELECT 1 FROM envelopes 
    WHERE last_transfer_chain_entry_signed_content_payload_checksum = $1
);

-- name: GetEnvelopeByLastChainEntrySignedContentPayloadChecksum :one
-- last_transfer_chain_entry_signed_content_payload_checksum is the checksum of the payload of the last transfer chain entry JWS token
-- and is unique for each transfer attempt
SELECT * FROM envelopes 
WHERE last_transfer_chain_entry_signed_content_payload_checksum = $1;

-- name: CreateEnvelope :one
-- Create a new envelope record for a transfer session if it doen't already exist.
-- A new envelope transfer is created for every new transfer chain entry received 
-- (based on the checksum of the payload of the last transfer chain entry JWS token)
-- envelopes.id is used as the envelope reference in the API responses.
INSERT INTO envelopes (
    id,
    created_at,
    updated_at,
    transport_document_checksum,
    action_code,
    last_transfer_chain_entry_signed_content_payload_checksum,
    sent_by_platform_code,
    envelope_manifest_signed_content,
    last_transfer_chain_entry_signed_content_checksum,
    last_transfer_chain_entry_signed_content,
    trust_level
) VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    sqlc.arg(transport_document_checksum),
    sqlc.arg(action_code),
    sqlc.arg(last_transfer_chain_entry_signed_content_payload_checksum),
    sqlc.arg(sent_by_platform_code),
    sqlc.arg(envelope_manifest_signed_content),
    sqlc.arg(last_transfer_chain_entry_signed_content_checksum),
    sqlc.arg(last_transfer_chain_entry_signed_content),
    sqlc.arg(trust_level)
) RETURNING *;

-- name: MarkEnvelopeAccepted :exec
-- Mark an envelope as accepted by setting accepted_at timestamp
UPDATE envelopes
SET accepted_at = NOW()
WHERE id = $1 AND accepted_at IS NULL;


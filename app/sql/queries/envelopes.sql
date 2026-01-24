-- Envelope queries for PINT API

-- name: CreateEnvelope :one
INSERT INTO envelopes (
    id,
    created_at,
    updated_at,
    envelope_reference,
    transport_document_reference,
    transport_document_checksum,
    transport_document,
    envelope_manifest_signed_content,
    last_transfer_chain_entry_signed_content,
    last_transfer_chain_entry_checksum,
    sender_platform,
    sender_ebl_platform,
    trust_level,
    state,
    response_code
) VALUES (
    gen_random_uuid(),
    now(),
    now(),
    gen_random_uuid(),
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
) RETURNING *;

-- name: GetEnvelopeByReference :one
SELECT * FROM envelopes
WHERE envelope_reference = $1;

-- name: GetEnvelopeByTransportDocumentChecksum :one
SELECT * FROM envelopes
WHERE transport_document_checksum = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: GetEnvelopeByLastChainChecksum :one
SELECT * FROM envelopes
WHERE last_transfer_chain_entry_checksum = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: GetEnvelopeByID :one
SELECT * FROM envelopes
WHERE id = $1;

-- name: UpdateEnvelopeState :exec
UPDATE envelopes
SET state = $2,
    response_code = $3,
    updated_at = now()
WHERE id = $1;

-- name: ListEnvelopes :many
SELECT * FROM envelopes
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;


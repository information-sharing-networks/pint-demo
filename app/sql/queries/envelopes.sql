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
    state
) VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: GetEnvelopeByReference :one
SELECT * FROM envelopes
WHERE envelope_reference = $1;

-- name: GetEnvelopeByID :one
SELECT * FROM envelopes
WHERE id = $1;

-- name: GetEnvelopeByTransportDocumentReference :one
SELECT * FROM envelopes
WHERE transport_document_reference = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: ListEnvelopesByTransportDocumentReference :many
SELECT * FROM envelopes
WHERE transport_document_reference = $1
ORDER BY created_at DESC;

-- name: UpdateEnvelopeState :execrows
UPDATE envelopes
SET (updated_at, state, response_code) = (now(), $2, $3)
WHERE id = $1;

-- name: ListEnvelopes :many
SELECT * FROM envelopes
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountEnvelopesByState :one
SELECT COUNT(*) FROM envelopes
WHERE state = $1;


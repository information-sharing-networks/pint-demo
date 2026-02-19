-- name: GetTransferChainEntriesByTransportDocumentChecksum :many
-- Get all transfer chain entries for a given eBL
-- Returns entries ordered by sequence
SELECT * FROM transfer_chain_entries
WHERE transport_document_checksum = $1
ORDER BY sequence ASC;

-- name: GetTransferChainEntryByPayloadChecksum :one
-- Get a specific transfer chain entry by its payload checksum
SELECT * FROM transfer_chain_entries
WHERE signed_content_payload_checksum = $1;

-- name: GetTransferChainEntryByJWSChecksum :one
-- Get a specific transfer chain entry by its JWS checksum
SELECT * FROM transfer_chain_entries
WHERE signed_content_checksum = $1;

-- name: ListTransferChainEntries :many
-- Get all transfer chain entries for a given envelope
-- Returns entries ordered by sequence
SELECT * FROM transfer_chain_entries
WHERE envelope_id = $1
ORDER BY sequence ASC;

-- name: CreateTransferChainEntry :one
-- Create a new transfer chain entry
INSERT INTO transfer_chain_entries (
    signed_content_payload_checksum,
    transport_document_checksum,
    envelope_id,
    signed_content,
    signed_content_checksum,
    previous_signed_content_checksum,
    sequence
) VALUES (
    sqlc.arg(signed_content_payload_checksum),
    sqlc.arg(transport_document_checksum),
    sqlc.arg(envelope_id),
    sqlc.arg(signed_content),
    sqlc.arg(signed_content_checksum),
    sqlc.arg(previous_signed_content_checksum),
    sqlc.arg(sequence)
) RETURNING *;


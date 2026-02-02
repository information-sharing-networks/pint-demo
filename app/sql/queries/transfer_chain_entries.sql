-- name: GetTransferChainEntriesByTransportDocumentChecksum :many
-- Get all transfer chain entries for a given eBL 
-- Returns entries ordered by creation time
SELECT * FROM transfer_chain_entries
WHERE transport_document_checksum = $1
ORDER BY created_at ASC;

-- name: GetTransferChainEntryByChecksum :one
-- Get a specific transfer chain entry by its checksum
SELECT * FROM transfer_chain_entries
WHERE entry_checksum = $1;

-- name: ListTransferChainEntries :many
-- Get all transfer chain entries for a given envelope
-- Returns entries ordered by sequence
SELECT * FROM transfer_chain_entries
WHERE envelope_id = $1
ORDER BY sequence ASC;

-- name: CreateTransferChainEntry :one
-- Create a new transfer chain entry
-- NOTE: Caller is responsible for DISE validation before calling this
INSERT INTO transfer_chain_entries (
    id,
    created_at,
    transport_document_checksum,
    envelope_id,
    signed_content,
    entry_checksum,
    previous_entry_checksum,
    sequence
) VALUES (
    gen_random_uuid(),
    NOW(),
    sqlc.arg(transport_document_checksum),
    sqlc.arg(envelope_id),
    sqlc.arg(signed_content),
    sqlc.arg(entry_checksum),
    sqlc.arg(previous_entry_checksum),
    sqlc.arg(sequence)
) RETURNING *;


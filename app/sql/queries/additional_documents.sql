-- Additional document queries for PINT API

-- name: CreateExpectedAdditionalDocument :one
-- Create a placeholder record for an expected additional document (not yet received)
INSERT INTO additional_documents (
    id,
    created_at,
    updated_at,
    envelope_id,
    document_checksum,
    document_name,
    document_size,
    media_type,
    is_ebl_visualisation,
    document_content,
    received_at,
    last_error_at,
    last_error_message
) VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1, $2, $3, $4, $5, $6, NULL, NULL, NULL, NULL
) RETURNING *;

-- name: StoreAdditionalDocument :one
-- Update an expected document with the actual content when received
UPDATE additional_documents
SET
    document_content = $2,
    received_at = now(),
    updated_at = now(),
    last_error_at = NULL,
    last_error_message = NULL
WHERE envelope_id = $1 AND document_checksum = $3
RETURNING *;

-- name: RecordAdditionalDocumentError :one
-- Record an error that occurred during document transfer
UPDATE additional_documents
SET
    last_error_at = now(),
    last_error_message = $3,
    updated_at = now()
WHERE envelope_id = $1 AND document_checksum = $2
RETURNING *;

-- name: GetAdditionalDocument :one
-- Get a specific additional document by envelope and checksum
SELECT * FROM additional_documents
WHERE envelope_id = $1 AND document_checksum = $2;

-- name: ListAdditionalDocumentsByEnvelope :many
-- List all additional documents for an envelope
SELECT * FROM additional_documents
WHERE envelope_id = $1
ORDER BY created_at;

-- name: ListMissingAdditionalDocuments :many
-- List all additional documents that have not yet been received for an envelope
SELECT * FROM additional_documents
WHERE envelope_id = $1 AND received_at IS NULL
ORDER BY created_at;

-- name: ListReceivedAdditionalDocuments :many
-- List all additional documents that have been received for an envelope
SELECT * FROM additional_documents
WHERE envelope_id = $1 AND received_at IS NOT NULL
ORDER BY received_at;

-- name: CountMissingAdditionalDocuments :one
-- Count how many additional documents are still missing for an envelope
SELECT COUNT(*) FROM additional_documents
WHERE envelope_id = $1 AND received_at IS NULL;

-- name: GetReceivedAdditionalDocumentChecksums :many
-- Get checksums of all received additional documents for an envelope
SELECT document_checksum FROM additional_documents
WHERE envelope_id = $1 AND received_at IS NOT NULL
ORDER BY received_at;


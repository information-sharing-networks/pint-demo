-- name: GetMissingAdditionalDocumentChecksums :many
-- Get checksums of additional documents that haven't been received yet
SELECT document_checksum FROM additional_documents
WHERE envelope_id = $1
  AND document_content IS NULL
ORDER BY document_checksum;

-- name: GetReceivedAdditionalDocumentChecksums :many
-- Get checksums of additional documents that have been received
SELECT document_checksum FROM additional_documents
WHERE envelope_id = $1
  AND document_content IS NOT NULL
ORDER BY document_checksum;

-- name: CreateExpectedAdditionalDocument :one
-- Create a placeholder record for an expected additional document
INSERT INTO additional_documents (
    id,
    created_at,
    envelope_id,
    document_checksum,
    document_name,
    expected_size,
    media_type,
    is_ebl_visualisation,
    document_content,
    received_at
) VALUES (
    gen_random_uuid(),
    NOW(),
    sqlc.arg(envelope_id),
    sqlc.arg(document_checksum),
    sqlc.arg(document_name),
    sqlc.arg(expected_size),
    sqlc.arg(media_type),
    sqlc.arg(is_ebl_visualisation),
    NULL, -- document_content (not received yet)
    NULL  -- received_at (not received yet)
) RETURNING *;

-- name: GetAdditionalDocument :one
SELECT * FROM additional_documents
WHERE envelope_id = $1
  AND document_checksum = $2;

-- name: UpdateAdditionalDocumentContent :exec
-- Update additional document with received content
UPDATE additional_documents
SET 
    document_content = $3,
    received_at = NOW()
WHERE envelope_id = $1
  AND document_checksum = $2;


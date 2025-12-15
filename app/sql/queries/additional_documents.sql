-- name: CreateAdditionalDocument :one
INSERT INTO additional_documents (
    id,
    created_at,
    envelope_id,
    document_checksum,
    document_content,
    media_type,
    is_ebl_visualisation
) VALUES (
    gen_random_uuid(),
    now(),
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetAdditionalDocument :one
SELECT * FROM additional_documents
WHERE envelope_id = $1 AND document_checksum = $2;

-- name: ListAdditionalDocumentsByEnvelope :many
SELECT * FROM additional_documents
WHERE envelope_id = $1
ORDER BY created_at ASC;

-- name: CountAdditionalDocumentsByEnvelope :one
SELECT COUNT(*) FROM additional_documents
WHERE envelope_id = $1;

-- name: GetAdditionalDocumentChecksums :many
SELECT document_checksum FROM additional_documents
WHERE envelope_id = $1
ORDER BY created_at ASC;


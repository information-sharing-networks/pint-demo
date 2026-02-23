-- name: CreateTransportDocumentIfNew :one
-- Insert transport document if it doesn't exist, otherwise return existing
-- This is used when receiving a new envelope transfer
INSERT INTO transport_documents (
    checksum,
    created_at,
    content
) VALUES (
    sqlc.arg(checksum),
    NOW(),
    sqlc.arg(content)
)
ON CONFLICT (checksum) DO NOTHING
RETURNING *;

-- name: GetTransportDocument :one
-- Get transport document by checksum
SELECT * FROM transport_documents
WHERE checksum = $1;


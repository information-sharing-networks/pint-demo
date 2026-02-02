-- name: UpsertTransportDocument :one
-- Insert transport document if it doesn't exist, otherwise return existing
-- This is used when receiving a new envelope transfer
INSERT INTO transport_documents (
    checksum,
    content,
    first_seen_at,
    first_received_from_platform_code
) VALUES (
    sqlc.arg(checksum),
    sqlc.arg(content),
    NOW(),
    sqlc.arg(first_received_from_platform_code)
)
ON CONFLICT (checksum) DO NOTHING
RETURNING *;

-- name: GetTransportDocument :one
-- Get transport document by checksum
SELECT * FROM transport_documents
WHERE checksum = $1;


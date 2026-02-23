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

-- name: GetTransportDocumentPossessor :one
-- Get the platform that currently possesses the eBL.
-- Possession is established by the most recently accepted ISSUE, TRANSFER, or SACC action in the chain.
SELECT id AS envelope_id,
    transport_document_checksum,
    action_code,
    received_by_platform_code AS possessor_platform_code,
    created_at,
    accepted_at
FROM envelopes
WHERE transport_document_checksum = $1
    AND accepted_at IS NOT NULL
    AND action_code IN ('ISSUE', 'TRANSFER', 'SACC')
ORDER BY accepted_at DESC
LIMIT 1;
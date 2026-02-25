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


-- name: GetTransportDocumentState :one
-- Get the current state of the eBL on this platform
SELECT * FROM transport_document_state
WHERE transport_document_checksum = $1;

-- name: GetTransportDocumentPossessor :one
-- Get the platform that currently possesses the eBL.
--
-- Note the platform may have accepted actions for eBLs they don't possess:
-- for insance, a transfer is pending additional docs, or it has received an endorsement 
-- action, but have not yet received the transfer action.
--
-- Use this query before determing what action to take when receiving a new envelope transfer.
SELECT * FROM transport_document_possessor
WHERE transport_document_checksum = $1;

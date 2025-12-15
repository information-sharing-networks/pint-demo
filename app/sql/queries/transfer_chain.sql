-- name: CreateTransferChainEntry :one
INSERT INTO transfer_chain_entries (
    id,
    created_at,
    envelope_id,
    signed_content,
    sequence
) VALUES (
    gen_random_uuid(),
    now(),
    $1, $2, $3
) RETURNING *;

-- name: ListTransferChainEntries :many
SELECT * FROM transfer_chain_entries
WHERE envelope_id = $1
ORDER BY sequence ASC;

-- name: GetLatestTransferChainEntry :one
SELECT * FROM transfer_chain_entries
WHERE envelope_id = $1
ORDER BY sequence DESC
LIMIT 1;

-- name: CountTransferChainEntries :one
SELECT COUNT(*) FROM transfer_chain_entries
WHERE envelope_id = $1;


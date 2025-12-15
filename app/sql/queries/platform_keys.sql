-- name: UpsertPlatformKey :one
INSERT INTO platform_keys (
    id,
    created_at,
    updated_at,
    platform_id,
    platform_name,
    jwks
) VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1, $2, $3
)
ON CONFLICT (platform_id)
DO UPDATE SET
    (updated_at, platform_name, jwks) = (now(), EXCLUDED.platform_name, EXCLUDED.jwks)
RETURNING *;

-- name: GetPlatformKey :one
SELECT * FROM platform_keys
WHERE platform_id = $1;

-- name: ListPlatformKeys :many
SELECT * FROM platform_keys
ORDER BY platform_id ASC;

-- name: DeletePlatformKey :exec
DELETE FROM platform_keys
WHERE platform_id = $1;


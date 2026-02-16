-- name: GetPartyByID :one
SELECT * FROM parties
WHERE id = $1;

-- name: GetPartyByPartyName :one
SELECT * FROM parties
WHERE party_name = $1;

-- name: CreateParty :one
INSERT INTO parties (id, created_at, updated_at, party_name, active)
VALUES (gen_random_uuid(), NOW(), NOW(), $1, $2)
RETURNING *;

-- name: UpdateParty :one
UPDATE parties
SET ( updated_at, party_name, active ) = (NOW(), $2, $3)
WHERE id = $1
RETURNING *;

-- name: CreatePartyIdentifyingCode :one
INSERT INTO party_identifying_codes (id, created_at,updated_at, party_id, code_list_provider, party_code, code_list_name)
VALUES (gen_random_uuid(), NOW(), NOW(), $1, $2, $3, $4)
RETURNING *;

-- name: GetPartyByPartyCode :one
-- Lookup a party by their identifying code (for receiver validation endpoint)
-- Only returns active parties
-- code_list_name is optional - if NULL, it matches any code_list_name
SELECT p.*
FROM parties p
INNER JOIN party_identifying_codes pic ON p.id = pic.party_id
WHERE pic.code_list_provider = sqlc.arg('code_list_provider')
  AND pic.party_code = sqlc.arg('party_code')
  AND (sqlc.narg('code_list_name')::text IS NULL OR pic.code_list_name = sqlc.narg('code_list_name')::text)
  AND p.active = TRUE
LIMIT 1;


-- name: PartyIdentifyingCodeExists :one
SELECT EXISTS(
    SELECT 1 FROM party_identifying_codes
    WHERE code_list_provider = $1
      AND party_code = $2
      AND (code_list_name = $3 OR code_list_name IS NULL)
);

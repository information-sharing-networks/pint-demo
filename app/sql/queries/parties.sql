-- name: GetPartyByID :one
SELECT * FROM parties
WHERE id = $1;

-- name: GetPartyByPartyName :one
SELECT * FROM parties
WHERE party_name = $1;

-- name: CreateParty :one
INSERT INTO parties (id, created_at, updated_at, party_name, active)
VALUES ($1, NOW(), NOW(), $2, true)
RETURNING *;

-- name: UpdateParty :one
UPDATE parties
SET ( updated_at, party_name, active ) = (NOW(), $2, $3)
WHERE id = $1
RETURNING *;

-- name: CreatePartyIdentifyingCode :one
INSERT INTO party_identifying_codes (id, created_at,updated_at, party_id, code_list_provider, party_code, code_list_name)
VALUES ($1, NOW(), NOW(), $2, $3, $4, $5)
RETURNING *;

-- name: GetPartyByPartyCode :one
-- Lookup a party by their identifying code (for receiver validation endpoint)
-- Only returns active parties
SELECT p.*
FROM parties p
INNER JOIN party_identifying_codes pic ON p.id = pic.party_id
WHERE pic.code_list_provider = $1
  AND pic.party_code = $2
  AND p.active = TRUE
LIMIT 1;


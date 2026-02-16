-- +goose Up

-- parties - Registry of parties (users/accounts) that can send/receive eBLs on this platform
CREATE TABLE parties (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Party information 
    party_name TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE
    
);

CREATE INDEX idx_parties_active ON parties(active);

-- party_identifying_codes - A party can have multiple codes from different providers (e.g., both a LEI and a DID)
CREATE TABLE party_identifying_codes (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Links to party
    party_id UUID NOT NULL,
    
    -- Identifying code details (per DCSA IdentifyingCode schema)
    code_list_provider TEXT NOT NULL, -- e.g., "GLEIF", "W3C", "DNB", "WAVE", "CARX"
    party_code TEXT NOT NULL, -- e.g., LEI number, DID, DUNS number, platform-specific ID
    code_list_name TEXT, -- Optional: e.g., "LEI", "DID", "DUNS"
    
    CONSTRAINT fk_party_identifying_codes_party FOREIGN KEY (party_id)
        REFERENCES parties(id)
        ON DELETE CASCADE
);

-- For non-NULL code_list_name
CREATE UNIQUE INDEX unique_identifying_code_with_name 
ON party_identifying_codes(code_list_provider, code_list_name, party_code)
WHERE code_list_name IS NOT NULL;

-- For NULL code_list_name
CREATE UNIQUE INDEX unique_identifying_code_without_name 
ON party_identifying_codes(code_list_provider, party_code)
WHERE code_list_name IS NULL;

CREATE INDEX idx_party_identifying_codes_party ON party_identifying_codes(party_id);
CREATE INDEX idx_party_identifying_codes_lookup ON party_identifying_codes(code_list_provider, party_code);

-- +goose Down
DROP TABLE IF EXISTS party_identifying_codes CASCADE;
DROP TABLE IF EXISTS parties CASCADE;


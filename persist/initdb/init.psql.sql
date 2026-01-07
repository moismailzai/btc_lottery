-- Create btc_addresses table if it doesn't exist
-- PRIMARY KEY already creates an implicit B-tree index
CREATE TABLE IF NOT EXISTS btc_addresses
(
    address TEXT PRIMARY KEY,
    balance BIGINT
);

-- Wallets table stores any matches found
CREATE TABLE IF NOT EXISTS wallets
(
    address     TEXT PRIMARY KEY,
    mnemonic    TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    addr_type   TEXT,
    found_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Misses table for debugging (optional, disabled by default)
CREATE TABLE IF NOT EXISTS misses
(
    address TEXT PRIMARY KEY
);

-- Note: No additional indexes needed
-- - btc_addresses.address: PRIMARY KEY provides B-tree index for lookups
-- - wallets.address: PRIMARY KEY provides B-tree index
-- - We never query wallets by private_key or public_key, so no indexes there

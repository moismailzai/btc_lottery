-- Create btc_addresses table if it doesn't exist
-- PRIMARY KEY already creates an implicit index, so no separate index needed
CREATE TABLE IF NOT EXISTS btc_addresses
(
    address TEXT PRIMARY KEY,
    balance BIGINT
);

-- Create other tables
CREATE TABLE IF NOT EXISTS wallets
(
    address     TEXT PRIMARY KEY,
    mnemonic    TEXT,
    private_key TEXT,
    public_key  TEXT
);

CREATE TABLE IF NOT EXISTS matches
(
    address TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS misses
(
    address TEXT PRIMARY KEY
);

-- Only create indexes on non-primary key columns that we search on
-- Note: PRIMARY KEY columns already have implicit indexes, so we don't duplicate those
DO
$$
    BEGIN
        -- Index on private_key for wallets (if we need to look up by private key)
        IF NOT EXISTS (SELECT 1
                       FROM pg_indexes
                       WHERE tablename = 'wallets'
                         AND indexname = 'idx_wallets_private_key') THEN
            CREATE INDEX idx_wallets_private_key ON wallets (private_key);
        END IF;

        -- Index on public_key for wallets (if we need to look up by public key)
        IF NOT EXISTS (SELECT 1
                       FROM pg_indexes
                       WHERE tablename = 'wallets'
                         AND indexname = 'idx_wallets_public_key') THEN
            CREATE INDEX idx_wallets_public_key ON wallets (public_key);
        END IF;
    END
$$;

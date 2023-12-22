-- Create btc_addresses table if it doesn't exist
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

-- Create indexes in a separate DO block
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'wallets' AND indexname = 'idx_wallets_address') THEN
            CREATE INDEX idx_wallets_address ON wallets (address);
        END IF;

        IF NOT EXISTS (SELECT 1
                       FROM pg_indexes
                       WHERE tablename = 'wallets'
                         AND indexname = 'idx_wallets_private_key') THEN
            CREATE INDEX idx_wallets_private_key ON wallets (private_key);
        END IF;

        IF NOT EXISTS (SELECT 1
                       FROM pg_indexes
                       WHERE tablename = 'wallets'
                         AND indexname = 'idx_wallets_public_key') THEN
            CREATE INDEX idx_wallets_public_key ON wallets (public_key);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'matches' AND indexname = 'idx_matches_address') THEN
            CREATE INDEX idx_matches_address ON matches (address);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'misses' AND indexname = 'idx_misses_address') THEN
            CREATE INDEX idx_misses_address ON misses (address);
        END IF;

        IF NOT EXISTS (SELECT 1
                       FROM pg_indexes
                       WHERE tablename = 'btc_addresses'
                         AND indexname = 'idx_btc_addresses_address') THEN
            CREATE INDEX idx_btc_addresses_address ON btc_addresses (address);
        END IF;
    END
$$;

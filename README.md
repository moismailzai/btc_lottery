# BTC Lottery

An educational demonstration of the practical impossibility of guessing Bitcoin private keys.

## The Premise

Bitcoin wallets are derived from a single number. If you could guess that number, you'd control the wallet. This program attempts exactly that: generate random wallet credentials and check if any match existing funded addresses.

**Spoiler: It won't work.** The keyspace is astronomically large (~2^128 for 12-word mnemonics). To store all possible addresses would require hard drives stacked 4.59×10^25 times the diameter of the Sun.

But it's fun to try.

## What It Does

1. Generates random BIP39 mnemonics (12 or 24 words)
2. Derives addresses using standard BIP derivation paths
3. Checks generated addresses against ~50 million known funded Bitcoin addresses
4. Logs any matches (there won't be any)

## Address Types Generated

For each mnemonic, the program derives multiple address types across multiple indexes:

| Type | BIP | Path | Format | Example Prefix |
|------|-----|------|--------|----------------|
| P2PKH | BIP44 | `m/44'/0'/0'/0/i` | Legacy | `1...` |
| P2SH-P2WPKH | BIP49 | `m/49'/0'/0'/0/i` | Wrapped SegWit | `3...` |
| P2WPKH | BIP84 | `m/84'/0'/0'/0/i` | Native SegWit | `bc1q...` |
| P2TR | BIP86 | `m/86'/0'/0'/0/i` | Taproot | `bc1p...` |

With default settings (20 indexes), each mnemonic produces **80 addresses** (4 types × 20 indexes).

## Performance Optimizations

- **Bloom Filter**: All ~50M addresses loaded into memory (~75MB) for O(1) negative lookups, eliminating 99%+ of database queries
- **Concurrent Workers**: Configurable worker pool (default 50) with independent local state
- **Batch Processing**: Addresses checked in batches using PostgreSQL `ANY()` array queries
- **Cursor Pagination**: Bloom filter initialization uses keyset pagination instead of slow OFFSET

## Quick Start

```bash
# 1. Start PostgreSQL
docker-compose up -d

# 2. Download address data (~2GB compressed)
curl -L -o blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz \
  http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz
gunzip blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz

# 3. Import into database (takes several minutes)
docker exec -it btc_lottery-postgres-1 psql -U btc -d btc -c \
  "\copy btc_addresses FROM '/blockchair_bitcoin_addresses_and_balance_LATEST.tsv' WITH (FORMAT text, DELIMITER E'\t', HEADER);"

# 4. Run
./build/btc_lottery -v
```

## Building

```bash
go mod download
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o build/btc_lottery btc_lottery.go
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-w` | 50 | Number of concurrent workers |
| `-b` | 1000 | Batch size for DB checks |
| `-i` | 20 | Address indexes per mnemonic (0 to n-1) |
| `-e` | 128 | Entropy bits: 128 (12 words) or 256 (24 words) |
| `-c` | 0 | Counter interval for progress logs (0 = disabled) |
| `-v` | false | Verbose output |
| `-db` | `postgres://btc:btc@localhost:5432/btc?sslmode=disable` | Database connection string |
| `-pt` | | Pushover application token |
| `-pu` | | Pushover user key |

## Running Tests

```bash
go test -v btc_lottery.go btc_lottery_test.go
```

Tests verify derivation correctness against known BIP test vectors using the standard "abandon" mnemonic.

## Data Source

Address data sourced from [Blockchair.com dumps](https://blockchair.com/dumps) via [addresses.loyce.club](http://addresses.loyce.club/).

## Database Schema

```sql
-- Known funded addresses (~50M rows)
CREATE TABLE btc_addresses (
    address TEXT PRIMARY KEY,
    balance BIGINT
);

-- Any matches found (will remain empty)
CREATE TABLE wallets (
    address     TEXT PRIMARY KEY,
    mnemonic    TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    addr_type   TEXT,
    found_at    TIMESTAMPTZ DEFAULT NOW()
);
```

## License

Educational use. Don't actually expect to find anything.

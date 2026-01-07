# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go application that generates random Bitcoin wallets (from 12 or 24-word BIP39 mnemonics) and checks if they match any existing funded addresses stored in a PostgreSQL database. It's an educational demonstration of the practical impossibility of guessing Bitcoin private keys.

## Build Commands

```shell
# Install dependencies
go mod download

# Build optimized binary for Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o build/btc_lottery btc_lottery.go

# Run tests (if any)
go test ./...
```

## Running the Application

```shell
# Start PostgreSQL database
docker-compose up -d

# Import address data (required before first run)
docker exec -it btc_lottery-postgres-1 psql -h localhost -U btc -d btc -c "\copy btc_addresses FROM '/blockchair_bitcoin_addresses_and_balance_LATEST.tsv' WITH (FORMAT text, DELIMITER E'\t', HEADER);"

# Run with verbose output for debugging
./build/btc_lottery -v

# Run with Pushover notifications
./build/btc_lottery -pt $PUSHOVER_APPLICATION_TOKEN -pu $PUSHOVER_USER_KEY
```

## Architecture

Single-file Go application (`btc_lottery.go`) with concurrent worker pattern:

- **Main goroutine**: Sets up database connection, initializes Bloom filter, spawns workers, handles graceful shutdown
- **Bloom filter**: All ~50M addresses loaded into memory for O(1) negative lookups, eliminating 99%+ of DB queries
- **Worker goroutines**: Each worker independently generates mnemonics, derives addresses, and batch-checks against the Bloom filter/database
- **Database**: PostgreSQL stores known Bitcoin addresses (`btc_addresses`) and any matches found (`wallets`)

Key flow:
1. Generate entropy → BIP39 mnemonic (128-bit/12-word default, or 256-bit/24-word with `-e 256`)
2. Derive master key using correct BIP paths:
   - BIP44 (`m/44'/0'/0'/0/index`) for P2PKH (legacy "1...") addresses
   - BIP49 (`m/49'/0'/0'/0/index`) for P2SH-P2WPKH (wrapped segwit "3...") addresses
   - BIP84 (`m/84'/0'/0'/0/index`) for P2WPKH (native segwit "bc1q...") addresses
3. Generate addresses for multiple indexes (default 0-19, configurable with `-i`)
4. Check addresses against Bloom filter first (fast rejection)
5. Only query database for Bloom filter positives (rare)
6. Log and store any matches found

## Database Schema

Defined in `persist/initdb/init.psql.sql`:
- `btc_addresses`: Known Bitcoin addresses with balances (imported from Blockchair dumps)
- `wallets`: Stores any matched wallet credentials (with addr_type and timestamp)
- `misses`: Optional table for recording non-matches (debug mode only)

## CLI Flags

Key flags: `-w` (workers), `-b` (batch size), `-i` (address indexes per mnemonic), `-e` (entropy bits: 128 or 256), `-v` (verbose), `-db` (connection string), `-pt`/`-pu` (Pushover tokens)

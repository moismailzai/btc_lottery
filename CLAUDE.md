# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go application that generates random Bitcoin wallets (from 12-word BIP39 mnemonics) and checks if they match any existing funded addresses stored in a PostgreSQL database. It's an educational demonstration of the practical impossibility of guessing Bitcoin private keys.

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

- **Main goroutine**: Sets up database connection, spawns workers, handles graceful shutdown
- **Worker goroutines**: Each worker independently generates mnemonics, derives addresses, and batch-checks against the database
- **Database**: PostgreSQL stores known Bitcoin addresses (`btc_addresses`) and any matches found (`wallets`)

Key flow:
1. Generate 128-bit entropy → 12-word BIP39 mnemonic
2. Derive master key → BIP44 child key (m/44'/0'/0'/0/0)
3. Generate both P2PKH (legacy "1...") and P2WPKH (segwit "bc1q...") addresses
4. Batch lookup addresses in database using `ANY($1::text[])` query
5. Log and store any matches found

## Database Schema

Defined in `persist/initdb/init.psql.sql`:
- `btc_addresses`: Known Bitcoin addresses with balances (imported from Blockchair dumps)
- `wallets`: Stores any matched wallet credentials
- `misses`: Optional table for recording non-matches (debug mode only)

## CLI Flags

Key flags: `-w` (workers), `-b` (batch size), `-v` (verbose), `-db` (connection string), `-pt`/`-pu` (Pushover tokens)

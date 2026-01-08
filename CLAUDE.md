# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go application that generates random Bitcoin wallets (from 12 or 24-word BIP39 mnemonics) and checks if they match any existing funded addresses loaded into memory. It's an educational demonstration of the practical impossibility of guessing Bitcoin private keys.

**Performance**: ~350,000 addresses/sec with 32 workers on AMD Ryzen 9 9950X3D.

## Build Commands

```shell
# Install dependencies
go mod download

# Build binary
go build -o build/btc_lottery ./cmd/btc_lottery

# Build optimized binary
go build -ldflags="-s -w" -o build/btc_lottery ./cmd/btc_lottery

# Build with GPU support (requires CUDA)
go build -tags cuda -o build/btc_lottery_gpu ./cmd/btc_lottery

# Run tests
go test ./internal/...
```

## Running the Application

```shell
# Download address data
curl -L -o addresses.tsv.gz http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz
gunzip addresses.tsv.gz

# Run with progress reporting every 5 seconds
./build/btc_lottery -addresses addresses.tsv -c 5

# Run with more workers
./build/btc_lottery -addresses addresses.tsv -w 50 -c 5

# Run with Pushover notifications
./build/btc_lottery -addresses addresses.tsv -pt $PUSHOVER_TOKEN -pu $PUSHOVER_USER
```

## Architecture

Multi-package Go application with concurrent worker pattern:

```
cmd/btc_lottery/     - Main entry point
├── main.go          - CLI parsing, orchestration
├── run_cpu.go       - CPU worker management
└── run_gpu.go       - GPU worker management (build tag: cuda)

internal/
├── lookup/          - In-memory address hash set
│   ├── hashset.go   - Sorted hash array with binary search
│   └── loader.go    - TSV file loader
└── worker/          - Worker implementations
    ├── interface.go - Common types (Match, Stats, Config)
    ├── cpu_worker.go- CPU-based address generation
    └── gpu_worker.go- GPU-accelerated (CUDA)

gpu/                 - Optional GPU support
├── cuda/            - CUDA kernels (.cu files)
├── gtable/          - Precomputed EC points generator
└── wrapper/         - Go-CUDA interface
```

### Key Components

- **AddressHashSet**: Sorted 8-byte hash prefixes for O(log n) binary search (~400MB for 50M addresses)
- **CPUWorker**: Uses btcd's hdkeychain for fast BIP32 derivation (48x faster than go-bip32)
- **Match logging**: Writes to `matches.log` with mutex protection

### Key Flow

1. Load addresses from TSV into sorted hash set
2. Spawn N worker goroutines
3. Each worker:
   - Generate entropy → BIP39 mnemonic
   - PBKDF2 → seed → master key
   - Cache hardened paths (m/44'/0'/0'/0, m/49'/0'/0'/0, m/84'/0'/0'/0, m/86'/0'/0'/0)
   - Derive 20 addresses per path type (80 total)
   - Binary search each address in hash set
   - Report matches

### Address Types

- BIP44 (`m/44'/0'/0'/0/i`): P2PKH (legacy "1...")
- BIP49 (`m/49'/0'/0'/0/i`): P2SH-P2WPKH (wrapped segwit "3...")
- BIP84 (`m/84'/0'/0'/0/i`): P2WPKH (native segwit "bc1q...")
- BIP86 (`m/86'/0'/0'/0/i`): P2TR (taproot "bc1p...")

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addresses` | | Path to TSV file (required) |
| `-w` | 32 | Number of workers |
| `-i` | 20 | Address indexes per mnemonic |
| `-e` | 128 | Entropy bits (128 or 256) |
| `-c` | 0 | Progress interval in seconds |
| `-v` | false | Verbose output |
| `-gpu` | false | Enable GPU acceleration |
| `-pt`/`-pu` | | Pushover tokens |

## Performance Notes

The main bottleneck is PBKDF2 (~0.54ms per mnemonic). BIP32 derivation using hdkeychain is very fast (~0.075ms for 4 hardened levels).

With 32 workers: ~4,400 mnemonics/sec × 80 addresses = ~350,000 addresses/sec.

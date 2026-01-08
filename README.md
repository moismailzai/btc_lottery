# BTC Lottery

An educational demonstration of the practical impossibility of guessing Bitcoin private keys.

## The Premise

Bitcoin wallets are derived from a single number. If you could guess that number, you'd control the wallet. This program attempts exactly that: generate random wallet credentials and check if any match existing funded addresses.

**Spoiler: It won't work.** The keyspace is astronomically large (~2^128 for 12-word mnemonics). To store all possible addresses would require hard drives stacked 4.59×10^25 times the diameter of the Sun.

But it's fun to try.

## Performance

| Metric | Value |
|--------|-------|
| Throughput | **~350,000 addresses/sec** (32 workers) |
| Memory usage | ~2.5 GB (for 50M addresses) |
| Time per mnemonic | ~2.3ms (80 addresses) |

Tested on AMD Ryzen 9 9950X3D with 94GB RAM.

## What It Does

1. Loads ~50 million known funded Bitcoin addresses into memory as a sorted hash set
2. Generates random BIP39 mnemonics (12 or 24 words)
3. Derives addresses using standard BIP derivation paths
4. Checks generated addresses against the in-memory hash set (O(log n) binary search)
5. Logs any matches (there won't be any)

## Address Types Generated

For each mnemonic, the program derives multiple address types across multiple indexes:

| Type | BIP | Path | Format | Example Prefix |
|------|-----|------|--------|----------------|
| P2PKH | BIP44 | `m/44'/0'/0'/0/i` | Legacy | `1...` |
| P2SH-P2WPKH | BIP49 | `m/49'/0'/0'/0/i` | Wrapped SegWit | `3...` |
| P2WPKH | BIP84 | `m/84'/0'/0'/0/i` | Native SegWit | `bc1q...` |
| P2TR | BIP86 | `m/86'/0'/0'/0/i` | Taproot | `bc1p...` |

With default settings (20 indexes), each mnemonic produces **80 addresses** (4 types × 20 indexes).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Main Process                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              In-Memory Address Hash Set                  │   │
│  │  • 50M addresses as sorted 8-byte hash prefixes (~400MB)│   │
│  │  • O(log n) binary search (~26 comparisons max)         │   │
│  │  • Full address strings for match verification (~1.7GB) │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              ↑                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐       ┌──────────┐    │
│  │ Worker 1 │ │ Worker 2 │ │ Worker 3 │  ...  │ Worker N │    │
│  │          │ │          │ │          │       │          │    │
│  │ Generate │ │ Generate │ │ Generate │       │ Generate │    │
│  │ Mnemonic │ │ Mnemonic │ │ Mnemonic │       │ Mnemonic │    │
│  │    ↓     │ │    ↓     │ │    ↓     │       │    ↓     │    │
│  │ PBKDF2   │ │ PBKDF2   │ │ PBKDF2   │       │ PBKDF2   │    │
│  │    ↓     │ │    ↓     │ │    ↓     │       │    ↓     │    │
│  │ Derive   │ │ Derive   │ │ Derive   │       │ Derive   │    │
│  │ 80 addrs │ │ 80 addrs │ │ 80 addrs │       │ 80 addrs │    │
│  │    ↓     │ │    ↓     │ │    ↓     │       │    ↓     │    │
│  │ Check    │ │ Check    │ │ Check    │       │ Check    │    │
│  └──────────┘ └──────────┘ └──────────┘       └──────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Key Optimizations

1. **In-Memory Hash Set**: Replaces PostgreSQL + Bloom filter with sorted hash array for O(log n) lookups
2. **hdkeychain Library**: Uses btcd's optimized BIP32 implementation (48x faster than go-bip32)
3. **Cached Derivation Paths**: Pre-computes hardened derivation paths (m/purpose'/0'/0'/0) once per mnemonic
4. **Concurrent Workers**: Independent goroutines with no lock contention

## Quick Start

```bash
# 1. Download address data (~2GB compressed)
curl -L -o addresses.tsv.gz \
  http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz
gunzip addresses.tsv.gz

# 2. Build
go build -o build/btc_lottery ./cmd/btc_lottery

# 3. Run
./build/btc_lottery -addresses addresses.tsv -c 5
```

## Building

```bash
# Standard build
go build -o build/btc_lottery ./cmd/btc_lottery

# Optimized build
go build -ldflags="-s -w" -o build/btc_lottery ./cmd/btc_lottery

# With GPU support (requires CUDA toolkit)
go build -tags cuda -o build/btc_lottery_gpu ./cmd/btc_lottery
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addresses` | | Path to TSV file with addresses (required) |
| `-w` | 32 | Number of concurrent workers |
| `-i` | 20 | Address indexes per mnemonic (0 to n-1) |
| `-e` | 128 | Entropy bits: 128 (12 words) or 256 (24 words) |
| `-c` | 0 | Progress report interval in seconds (0 = disabled) |
| `-v` | false | Verbose output |
| `-gpu` | false | Enable GPU acceleration |
| `-batch` | 12500 | GPU batch size in mnemonics |
| `-pt` | | Pushover application token |
| `-pu` | | Pushover user key |

## Example Output

```
2026/01/07 15:34:03 BTC Lottery v2 - GPU Accelerated
2026/01/07 15:34:03 Workers: 32, Address indexes: 20, Mnemonic: 12 words
2026/01/07 15:34:03 Loading addresses from addresses.tsv...
2026/01/07 15:34:45 Loaded 50000000 addresses (2.1 GB memory)
2026/01/07 15:34:50 Starting 32 CPU workers...
2026/01/07 15:34:55 Checked 1732560 addresses (346512/sec), 21684 mnemonics
2026/01/07 15:35:00 Checked 3498560 addresses (353200/sec), 43759 mnemonics
```

## Project Structure

```
btc_lottery/
├── cmd/btc_lottery/       # Main application entry point
│   ├── main.go            # CLI and orchestration
│   ├── run_cpu.go         # CPU worker management
│   └── run_gpu.go         # GPU worker management (build tag: cuda)
├── internal/
│   ├── lookup/            # In-memory address hash set
│   │   ├── hashset.go     # Sorted hash array with binary search
│   │   └── loader.go      # TSV file loader
│   └── worker/            # Worker implementations
│       ├── interface.go   # Common types
│       ├── cpu_worker.go  # CPU-based address generation
│       └── gpu_worker.go  # GPU-accelerated (CUDA)
├── gpu/                   # GPU support (optional)
│   ├── cuda/              # CUDA kernels
│   ├── gtable/            # Precomputed EC points generator
│   └── wrapper/           # Go-CUDA interface
└── testdata/              # Sample data for testing
```

## GPU Support

The codebase includes experimental GPU acceleration using CUDA. With the hdkeychain optimization, CPU performance is now excellent (~350k addresses/sec), so GPU is optional.

To build with GPU support:

```bash
# Compile CUDA kernels (requires nvcc)
cd gpu/cuda && make

# Generate GTable (precomputed EC points)
go run ./cmd/gengtable -o gpu/cuda/

# Build with cuda tag
go build -tags cuda -o build/btc_lottery_gpu ./cmd/btc_lottery
```

## Data Source

Address data sourced from [Blockchair.com dumps](https://blockchair.com/dumps) via [addresses.loyce.club](http://addresses.loyce.club/).

The TSV file should have two columns: `address` and `balance` (tab-separated with header).

## Technical Details

### Why hdkeychain?

The original go-bip32 library computed EC public keys for fingerprints on every child derivation (~1ms each). With 80 addresses per mnemonic, this added 80+ unnecessary EC operations.

btcd's hdkeychain uses lazy public key computation, reducing per-mnemonic time from 112ms to 2.3ms (48x improvement).

### Memory Layout

| Component | Memory |
|-----------|--------|
| Address hash prefixes (50M × 8 bytes) | ~400 MB |
| Full address strings (50M × ~34 bytes) | ~1.7 GB |
| Working buffers | ~400 MB |
| **Total** | ~2.5 GB |

## License

Educational use. Don't actually expect to find anything.

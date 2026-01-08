package worker

import (
	"context"
)

// Match represents a found address match.
type Match struct {
	Address    string
	PrivateKey string
	PublicKey  string
	Mnemonic   string
	AddrType   string
}

// Stats contains worker statistics.
type Stats struct {
	AddressesChecked int64
	MnemonicsGenerated int64
	MatchesFound     int64
}

// Worker defines the interface for address generation and checking.
type Worker interface {
	// Run starts the worker loop, returning matches on the channel.
	// Blocks until context is cancelled.
	Run(ctx context.Context) <-chan Match

	// Stats returns current statistics.
	Stats() Stats

	// Close releases any resources.
	Close() error
}

// Config contains worker configuration.
type Config struct {
	// Number of address indexes to check per mnemonic (0 to N-1)
	AddressIndexes int

	// Entropy bits: 128 (12 words) or 256 (24 words)
	EntropyBits int

	// GPU batch size in mnemonics (for GPU worker)
	GPUBatchSize int

	// Use GPU if available
	UseGPU bool

	// Verbose logging
	Verbose bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		AddressIndexes: 20,
		EntropyBits:    128,
		GPUBatchSize:   12500,
		UseGPU:         true,
		Verbose:        false,
	}
}

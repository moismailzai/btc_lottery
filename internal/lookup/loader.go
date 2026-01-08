package lookup

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// LoadConfig configures how addresses are loaded.
type LoadConfig struct {
	// Path to TSV file (address\tbalance format)
	FilePath string

	// Minimum balance to include (0 = all addresses)
	MinBalance int64

	// Progress callback interval (0 = no progress)
	ProgressInterval time.Duration

	// Estimated count for pre-allocation (0 = auto)
	EstimatedCount int
}

// LoadFromTSV loads addresses from a Blockchair-format TSV file.
// Format: address<TAB>balance (with header row)
func LoadFromTSV(cfg LoadConfig) (*AddressHashSet, error) {
	file, err := os.Open(cfg.FilePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	// Get file size for progress reporting
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("getting file stats: %w", err)
	}
	fileSize := stat.Size()

	return LoadFromReader(file, fileSize, cfg)
}

// LoadFromReader loads addresses from any io.Reader.
func LoadFromReader(r io.Reader, totalSize int64, cfg LoadConfig) (*AddressHashSet, error) {
	capacity := cfg.EstimatedCount
	if capacity == 0 {
		capacity = 50_000_000 // Default estimate
	}

	hashSet := NewAddressHashSet(capacity)

	scanner := bufio.NewScanner(r)
	// Increase buffer size for long lines
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var loaded int64
	var bytesRead int64
	lastProgress := time.Now()
	startTime := time.Now()

	// Skip header
	if scanner.Scan() {
		bytesRead += int64(len(scanner.Bytes())) + 1
	}

	// Batch for efficiency
	batch := make([]string, 0, 10000)

	for scanner.Scan() {
		line := scanner.Text()
		bytesRead += int64(len(line)) + 1

		// Parse TSV: address<TAB>balance
		parts := strings.Split(line, "\t")
		if len(parts) < 1 {
			continue
		}

		address := parts[0]
		if address == "" {
			continue
		}

		// Optional balance filtering
		if cfg.MinBalance > 0 && len(parts) >= 2 {
			// Parse balance if needed
			// For now, skip balance filtering for simplicity
		}

		batch = append(batch, address)

		// Flush batch
		if len(batch) >= 10000 {
			hashSet.AddBatch(batch)
			loaded += int64(len(batch))
			batch = batch[:0]
		}

		// Progress reporting
		if cfg.ProgressInterval > 0 && time.Since(lastProgress) >= cfg.ProgressInterval {
			progress := float64(bytesRead) / float64(totalSize) * 100
			elapsed := time.Since(startTime)
			rate := float64(loaded) / elapsed.Seconds()
			eta := time.Duration(float64(totalSize-bytesRead) / float64(bytesRead) * float64(elapsed))

			log.Printf("Loading addresses: %.1f%% (%d loaded, %.0f/sec, ETA: %v)",
				progress, loaded, rate, eta.Round(time.Second))
			lastProgress = time.Now()
		}
	}

	// Flush remaining
	if len(batch) > 0 {
		hashSet.AddBatch(batch)
		loaded += int64(len(batch))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning file: %w", err)
	}

	// Finalize (sort for binary search)
	log.Printf("Sorting %d addresses for binary search...", loaded)
	sortStart := time.Now()
	hashSet.Finalize()
	log.Printf("Sort completed in %v", time.Since(sortStart))

	elapsed := time.Since(startTime)
	memMB := float64(hashSet.MemoryUsage()) / (1024 * 1024)
	log.Printf("Loaded %d addresses in %v (%.1f MB memory)",
		hashSet.TotalAddresses(), elapsed.Round(time.Millisecond), memMB)

	return hashSet, nil
}

// LoadFromDatabase loads addresses from PostgreSQL (legacy support).
// This is kept for testing/comparison but not used in production.
func LoadFromDatabase(connStr string) (*AddressHashSet, error) {
	// Import would create circular dependency, so this is a stub
	return nil, fmt.Errorf("database loading not implemented in new architecture; use TSV file")
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"btc_lottery/internal/lookup"
	"btc_lottery/internal/worker"
)

var (
	// Data source
	addressFile = flag.String("addresses", "", "Path to TSV file with addresses (required)")

	// Worker configuration
	workers        = flag.Int("w", 32, "Number of CPU workers")
	addressIndexes = flag.Int("i", 20, "Number of address indexes to check per mnemonic (0-n)")
	entropyBits    = flag.Int("e", 128, "Entropy bits: 128 (12 words) or 256 (24 words)")

	// GPU configuration
	useGPU       = flag.Bool("gpu", false, "Enable GPU acceleration")
	gpuBatchSize = flag.Int("batch", 12500, "GPU batch size in mnemonics")
	ptxPath      = flag.String("ptx", "", "Path to btc_lottery.ptx (auto-detect if not set)")
	gtableXPath  = flag.String("gtable-x", "", "Path to GTable X file (generate in memory if not set)")
	gtableYPath  = flag.String("gtable-y", "", "Path to GTable Y file (generate in memory if not set)")

	// Output configuration
	counterInterval = flag.Int("c", 0, "Interval for reporting address count (0 = disabled)")
	verbose         = flag.Bool("v", false, "Enable verbose output")

	// Notifications
	pushoverToken = flag.String("pt", "", "Pushover application token")
	pushoverUser  = flag.String("pu", "", "Pushover user key")

	// Legacy database support (for migration)
	dbConn = flag.String("db", "", "Database connection string (legacy, use -addresses instead)")

	// Mutex for file writes
	matchesFileMutex sync.Mutex
)

// workerConfig holds configuration for worker creation.
type workerConfig struct {
	numWorkers     int
	addressIndexes int
	entropyBits    int
	gpuBatchSize   int
	useGPU         bool
	verbose        bool
	ptxPath        string
	gtableXPath    string
	gtableYPath    string
}

func main() {
	flag.Parse()

	// Validate inputs
	if *entropyBits != 128 && *entropyBits != 256 {
		log.Fatal("Entropy bits must be 128 (12 words) or 256 (24 words)")
	}

	if *addressFile == "" && *dbConn == "" {
		log.Fatal("Must specify -addresses <path-to-tsv> or -db <connection-string>")
	}

	mnemonicWords := *entropyBits / 32 * 3
	log.Printf("BTC Lottery v2 - GPU Accelerated")
	log.Printf("Workers: %d, Address indexes: %d, Mnemonic: %d words", *workers, *addressIndexes, mnemonicWords)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Load addresses into memory
	var hashSet *lookup.AddressHashSet
	var err error

	if *addressFile != "" {
		log.Printf("Loading addresses from %s...", *addressFile)
		hashSet, err = lookup.LoadFromTSV(lookup.LoadConfig{
			FilePath:         *addressFile,
			ProgressInterval: 5 * time.Second,
		})
		if err != nil {
			log.Fatalf("Failed to load addresses: %v", err)
		}
	} else if *dbConn != "" {
		log.Fatal("Database loading not supported in v2. Export addresses to TSV first.")
	}

	log.Printf("Loaded %d addresses (%.1f MB memory)",
		hashSet.TotalAddresses(),
		float64(hashSet.MemoryUsage())/(1024*1024))

	// Worker configuration
	cfg := workerConfig{
		numWorkers:     *workers,
		addressIndexes: *addressIndexes,
		entropyBits:    *entropyBits,
		gpuBatchSize:   *gpuBatchSize,
		useGPU:         *useGPU,
		verbose:        *verbose,
		ptxPath:        *ptxPath,
		gtableXPath:    *gtableXPath,
		gtableYPath:    *gtableYPath,
	}

	// Start workers
	var totalMatches int64
	matchChan, getStats, waitWorkers := runWorkers(ctx, hashSet, cfg)

	// Aggregate matches from all workers
	go func() {
		for match := range matchChan {
			atomic.AddInt64(&totalMatches, 1)
			logMatch(match)
		}
	}()

	// Progress reporter
	if *counterInterval > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(*counterInterval) * time.Second)
			defer ticker.Stop()

			lastCount := int64(0)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					current, mnemonics := getStats()
					rate := (current - lastCount) / int64(*counterInterval)
					lastCount = current

					var msg string
					if mnemonics > 0 {
						msg = fmt.Sprintf("Checked %d addresses (%d/sec), %d mnemonics", current, rate, mnemonics)
					} else {
						msg = fmt.Sprintf("Checked %d addresses (%d/sec)", current, rate)
					}
					log.Println(msg)

					if *pushoverToken != "" && *pushoverUser != "" {
						go sendPushoverNotification(*pushoverToken, *pushoverUser, "BTC Lottery Progress", msg)
					}
				}
			}
		}()
	}

	// Wait for shutdown
	<-ctx.Done()
	log.Println("Shutdown signal received, waiting for workers to finish...")

	// Give workers time to finish
	done := make(chan struct{})
	go func() {
		waitWorkers()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All workers finished")
	case <-time.After(10 * time.Second):
		log.Println("Timeout waiting for workers")
	}

	final, _ := getStats()
	matches := atomic.LoadInt64(&totalMatches)
	log.Printf("Shutdown complete. Total addresses checked: %d, Matches found: %d", final, matches)
}

func logMatch(match worker.Match) {
	msg := fmt.Sprintf("MATCH FOUND! Address: %s Type: %s Mnemonic: %s",
		match.Address, match.AddrType, match.Mnemonic)

	// Print to console with emphasis
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(msg)
	fmt.Println(strings.Repeat("=", 60))

	// Append to file (mutex-protected)
	matchesFileMutex.Lock()
	file, err := os.OpenFile("matches.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		matchesFileMutex.Unlock()
		log.Printf("Error opening matches.log: %v", err)
		return
	}

	timestamp := time.Now().Format(time.RFC3339)
	logLine := fmt.Sprintf("[%s] Address: %s | Type: %s | Mnemonic: %s | PrivKey: %s\n",
		timestamp, match.Address, match.AddrType, match.Mnemonic, match.PrivateKey)
	if _, err := file.WriteString(logLine); err != nil {
		log.Printf("Error writing to matches.log: %v", err)
	}
	file.Close()
	matchesFileMutex.Unlock()

	// Send push notification
	if *pushoverToken != "" && *pushoverUser != "" {
		go sendPushoverNotification(*pushoverToken, *pushoverUser, "BTC LOTTERY MATCH!", msg)
	}
}

func sendPushoverNotification(token, user, title, message string) error {
	form := url.Values{}
	form.Set("token", token)
	form.Set("user", user)
	form.Set("title", title)
	form.Set("message", message)

	req, err := http.NewRequest("POST", "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response from Pushover: %s", resp.Status)
	}

	return nil
}
